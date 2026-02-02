"""
Entity Models

Pydantic v2 models for SPECTRE entities following STIX 2.1 semantics.
These models represent the core data structures stored in the entity graph.
"""

from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)


class HashType(str, Enum):
    """Types of cryptographic hashes."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    SSDEEP = "ssdeep"
    TLSH = "tlsh"
    IMPHASH = "imphash"


class DNSRecordType(str, Enum):
    """DNS record types."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    PTR = "PTR"
    SRV = "SRV"
    CAA = "CAA"


class BaseEntity(BaseModel):
    """
    Base class for all SPECTRE entities.

    Provides common fields and behaviors following STIX 2.1 patterns.
    """

    model_config = ConfigDict(
        extra="allow",
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    id: UUID = Field(default_factory=uuid4, description="Unique entity identifier")
    type: str = Field(..., description="Entity type identifier")
    created: datetime = Field(
        default_factory=datetime.utcnow, description="When the entity was created"
    )
    modified: datetime = Field(
        default_factory=datetime.utcnow, description="When the entity was last modified"
    )
    first_seen: datetime | None = Field(
        default=None, description="When this entity was first observed"
    )
    last_seen: datetime | None = Field(
        default=None, description="When this entity was last observed"
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence score for this entity (0-1)",
    )
    sources: list[str] = Field(
        default_factory=list, description="Sources that reported this entity"
    )
    tags: list[str] = Field(default_factory=list, description="Tags/labels for this entity")
    notes: str | None = Field(default=None, description="Additional notes")
    external_references: list[dict[str, Any]] = Field(
        default_factory=list, description="External references (URLs, reports, etc.)"
    )

    def add_source(self, source: str) -> None:
        """Add a source to this entity."""
        if source not in self.sources:
            self.sources.append(source)

    def add_tag(self, tag: str) -> None:
        """Add a tag to this entity."""
        if tag not in self.tags:
            self.tags.append(tag)

    def update_seen(self, seen_time: datetime | None = None) -> None:
        """Update first_seen and last_seen timestamps."""
        now = seen_time or datetime.utcnow()
        if self.first_seen is None or now < self.first_seen:
            self.first_seen = now
        if self.last_seen is None or now > self.last_seen:
            self.last_seen = now
        self.modified = datetime.utcnow()

    def to_stix(self) -> dict[str, Any]:
        """Convert to STIX 2.1 format (basic implementation)."""
        return {
            "type": self.type,
            "id": f"{self.type}--{self.id}",
            "created": self.created.isoformat(),
            "modified": self.modified.isoformat(),
        }


class DNSRecord(BaseModel):
    """A DNS record."""

    model_config = ConfigDict(extra="allow")

    record_type: DNSRecordType
    value: str
    ttl: int | None = None
    priority: int | None = None  # For MX records


class Domain(BaseEntity):
    """
    Domain entity.

    Represents a domain name with associated DNS records and registration information.
    """

    type: str = Field(default="domain", frozen=True)
    value: str = Field(..., description="The domain name", min_length=1)

    # DNS Information
    dns_records: list[DNSRecord] = Field(
        default_factory=list, description="DNS records for this domain"
    )
    nameservers: list[str] = Field(
        default_factory=list, description="Authoritative nameservers"
    )

    # WHOIS Information
    registrar: str | None = Field(default=None, description="Domain registrar")
    registrant_name: str | None = Field(default=None, description="Registrant name")
    registrant_organization: str | None = Field(
        default=None, description="Registrant organization"
    )
    registrant_email: str | None = Field(default=None, description="Registrant email")
    registrant_country: str | None = Field(default=None, description="Registrant country")
    creation_date: datetime | None = Field(
        default=None, description="Domain registration date"
    )
    expiration_date: datetime | None = Field(
        default=None, description="Domain expiration date"
    )
    updated_date: datetime | None = Field(
        default=None, description="Last WHOIS update date"
    )

    # Relationships (stored as IDs for graph storage)
    resolves_to: list[str] = Field(
        default_factory=list, description="IP addresses this domain resolves to"
    )
    subdomains: list[str] = Field(
        default_factory=list, description="Known subdomains"
    )
    parent_domain: str | None = Field(
        default=None, description="Parent domain if this is a subdomain"
    )

    # Threat Intelligence
    is_malicious: bool | None = Field(
        default=None, description="Whether this domain is known malicious"
    )
    threat_types: list[str] = Field(
        default_factory=list, description="Types of threats associated"
    )

    @field_validator("value")
    @classmethod
    def normalize_domain(cls, v: str) -> str:
        """Normalize domain to lowercase without trailing dot."""
        return v.lower().rstrip(".")

    def add_dns_record(
        self,
        record_type: DNSRecordType,
        value: str,
        ttl: int | None = None,
        priority: int | None = None,
    ) -> None:
        """Add a DNS record to this domain."""
        record = DNSRecord(
            record_type=record_type, value=value, ttl=ttl, priority=priority
        )
        # Avoid duplicates
        if record not in self.dns_records:
            self.dns_records.append(record)

    def get_records_by_type(self, record_type: DNSRecordType) -> list[DNSRecord]:
        """Get all DNS records of a specific type."""
        return [r for r in self.dns_records if r.record_type == record_type]

    def to_stix(self) -> dict[str, Any]:
        """Convert to STIX 2.1 domain-name object."""
        stix = super().to_stix()
        stix.update(
            {
                "type": "domain-name",
                "value": self.value,
            }
        )
        if self.resolves_to:
            stix["resolves_to_refs"] = [
                f"ipv4-addr--{ip}" if "." in ip else f"ipv6-addr--{ip}"
                for ip in self.resolves_to
            ]
        return stix


class IPAddress(BaseEntity):
    """
    IP Address entity.

    Represents an IPv4 or IPv6 address with associated metadata.
    """

    type: str = Field(default="ip_address", frozen=True)
    value: str = Field(..., description="The IP address")
    version: int = Field(default=4, description="IP version (4 or 6)")

    # Network Information
    asn: int | None = Field(default=None, description="Autonomous System Number")
    asn_name: str | None = Field(default=None, description="ASN organization name")
    asn_country: str | None = Field(default=None, description="ASN country code")

    # Geolocation
    country: str | None = Field(default=None, description="Country code")
    country_name: str | None = Field(default=None, description="Country name")
    region: str | None = Field(default=None, description="Region/state")
    city: str | None = Field(default=None, description="City")
    latitude: float | None = Field(default=None, description="Latitude")
    longitude: float | None = Field(default=None, description="Longitude")

    # Services
    open_ports: list[int] = Field(default_factory=list, description="Open ports")
    services: list[dict[str, Any]] = Field(
        default_factory=list, description="Detected services"
    )

    # Relationships
    hosts_domains: list[str] = Field(
        default_factory=list, description="Domains hosted on this IP"
    )
    belongs_to_asn: str | None = Field(default=None, description="Parent ASN ID")

    # Threat Intelligence
    is_malicious: bool | None = Field(
        default=None, description="Whether this IP is known malicious"
    )
    threat_types: list[str] = Field(
        default_factory=list, description="Types of threats associated"
    )
    flagged_by: list[str] = Field(
        default_factory=list, description="Threat feeds that flagged this IP"
    )

    @model_validator(mode="after")
    def validate_and_set_version(self) -> "IPAddress":
        """Validate IP address and set version."""
        try:
            IPv4Address(self.value)
            self.version = 4
        except ValueError:
            try:
                IPv6Address(self.value)
                self.version = 6
            except ValueError:
                raise ValueError(f"Invalid IP address: {self.value}")
        return self

    def to_stix(self) -> dict[str, Any]:
        """Convert to STIX 2.1 ipv4-addr or ipv6-addr object."""
        stix = super().to_stix()
        stix_type = "ipv4-addr" if self.version == 4 else "ipv6-addr"
        stix.update(
            {
                "type": stix_type,
                "value": self.value,
            }
        )
        if self.belongs_to_asn:
            stix["belongs_to_refs"] = [f"autonomous-system--{self.belongs_to_asn}"]
        return stix


class Email(BaseEntity):
    """
    Email address entity.

    Represents an email address with associated metadata.
    """

    type: str = Field(default="email", frozen=True)
    value: EmailStr = Field(..., description="The email address")

    # Parsed components
    local_part: str = Field(default="", description="Local part of the email")
    domain: str = Field(default="", description="Domain part of the email")

    # Provider Information
    provider: str | None = Field(default=None, description="Email provider")
    is_free_provider: bool | None = Field(
        default=None, description="Whether it's a free email provider"
    )
    is_disposable: bool | None = Field(
        default=None, description="Whether it's a disposable email"
    )

    # Breach Information
    breach_count: int = Field(default=0, description="Number of known breaches")
    breaches: list[str] = Field(
        default_factory=list, description="List of breach names"
    )

    # Relationships
    associated_domains: list[str] = Field(
        default_factory=list, description="Domains registered with this email"
    )
    belongs_to_person: str | None = Field(
        default=None, description="Associated person ID"
    )

    @model_validator(mode="after")
    def parse_email_parts(self) -> "Email":
        """Parse email into local and domain parts."""
        if "@" in str(self.value):
            parts = str(self.value).split("@", 1)
            self.local_part = parts[0]
            self.domain = parts[1] if len(parts) > 1 else ""
        return self

    def to_stix(self) -> dict[str, Any]:
        """Convert to STIX 2.1 email-addr object."""
        stix = super().to_stix()
        stix.update(
            {
                "type": "email-addr",
                "value": str(self.value),
            }
        )
        return stix


# Valid hash lengths for validation
HASH_LENGTHS = {
    HashType.MD5: 32,
    HashType.SHA1: 40,
    HashType.SHA256: 64,
    HashType.SHA512: 128,
}


class Hash(BaseEntity):
    """
    Hash/IOC entity.

    Represents a cryptographic hash (MD5, SHA1, SHA256, etc.).
    """

    type: str = Field(default="hash", frozen=True)
    value: str = Field(..., description="The hash value")
    hash_type: HashType = Field(..., description="Type of hash")

    # Associated File Information
    file_name: str | None = Field(default=None, description="Original file name")
    file_size: int | None = Field(default=None, description="File size in bytes")
    file_type: str | None = Field(default=None, description="File MIME type")

    # Malware Information
    malware_family: str | None = Field(
        default=None, description="Associated malware family"
    )
    malware_names: list[str] = Field(
        default_factory=list, description="AV detection names"
    )

    # Threat Intelligence
    is_malicious: bool | None = Field(
        default=None, description="Whether this hash is known malicious"
    )
    detection_ratio: str | None = Field(
        default=None, description="Detection ratio (e.g., '45/70')"
    )
    threat_types: list[str] = Field(
        default_factory=list, description="Types of threats associated"
    )

    # Relationships
    communicates_with: list[str] = Field(
        default_factory=list, description="IPs/domains this malware communicates with"
    )
    distributed_via: list[str] = Field(
        default_factory=list, description="URLs distributing this file"
    )

    @field_validator("value")
    @classmethod
    def normalize_hash(cls, v: str) -> str:
        """Normalize hash to lowercase."""
        return v.lower()

    @model_validator(mode="after")
    def validate_hash_length(self) -> "Hash":
        """Validate hash length matches the type."""
        expected_length = HASH_LENGTHS.get(self.hash_type)
        if expected_length and len(self.value) != expected_length:
            raise ValueError(
                f"Invalid {self.hash_type.value} hash length: "
                f"expected {expected_length}, got {len(self.value)}"
            )
        return self

    def to_stix(self) -> dict[str, Any]:
        """Convert to STIX 2.1 file object with hash."""
        stix = super().to_stix()
        stix.update(
            {
                "type": "file",
                "hashes": {self.hash_type.value.upper(): self.value},
            }
        )
        if self.file_name:
            stix["name"] = self.file_name
        if self.file_size:
            stix["size"] = self.file_size
        return stix


# Type alias for any entity
AnyEntity = Annotated[
    Domain | IPAddress | Email | Hash,
    Field(discriminator="type"),
]
