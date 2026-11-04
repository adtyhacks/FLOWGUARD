"""Default product and coupon seed data for ShopZone."""

from sqlalchemy.orm import Session
from .models import Coupon, Product

# Standard product catalog with integer minor units (e.g., paise: 150000 = ₹1500.00)
SEED_PRODUCTS = [
    {
        "id": 1,
        "name": "FlowGuard Security Key Pro",
        "description": "Hardware FIDO2 WebAuthn cryptographic security key with NFC support.",
        "price_minor_units": 450000,  # 4500.00
        "stock": 50,
    },
    {
        "id": 2,
        "name": "Encrypted USB Storage 64GB",
        "description": "Hardware AES-256 encrypted flash drive with physical keypad PIN authentication.",
        "price_minor_units": 890000,  # 8900.00
        "stock": 35,
    },
    {
        "id": 3,
        "name": "Privacy Webcam Cover (Pack of 3)",
        "description": "Ultra-thin mechanical slide webcam cover for laptops, tablets, and smartphones.",
        "price_minor_units": 49900,  # 499.00
        "stock": 200,
    },
    {
        "id": 4,
        "name": "RFID Blocking Passport Sleeve",
        "description": "High-attenuation aluminum composite RFID shielding sleeve preventing wireless skimming.",
        "price_minor_units": 79900,  # 799.00
        "stock": 100,
    },
    {
        "id": 5,
        "name": "Network Packet Sniffer Adapter",
        "description": "Dual-band USB monitoring adapter supporting monitor mode and packet injection.",
        "price_minor_units": 320000,  # 3200.00
        "stock": 40,
    },
]

# Standard coupon codes
SEED_COUPONS = [
    {
        "id": 1,
        "code": "CYBERSEC20",
        "discount_pct": 20,
        "max_uses": 1,  # Globally single-use
        "times_used": 0,
        "is_active": True,
    },
    {
        "id": 2,
        "code": "WELCOME10",
        "discount_pct": 10,
        "max_uses": 1,  # Globally single-use
        "times_used": 0,
        "is_active": True,
    },
    {
        "id": 3,
        "code": "STUDENT50",
        "discount_pct": 50,
        "max_uses": 1,  # Single-use heavy discount
        "times_used": 0,
        "is_active": True,
    },
]


def seed_database(session: Session) -> None:
    """Populate database with initial products and coupons if not already present."""
    # Seed Products
    for prod_data in SEED_PRODUCTS:
        existing = session.query(Product).filter_by(id=prod_data["id"]).first()
        if not existing:
            product = Product(
                id=prod_data["id"],
                name=prod_data["name"],
                description=prod_data["description"],
                price_minor_units=prod_data["price_minor_units"],
                stock=prod_data["stock"],
            )
            session.add(product)
            
    # Seed Coupons
    for cpn_data in SEED_COUPONS:
        existing = session.query(Coupon).filter_by(code=cpn_data["code"]).first()
        if not existing:
            coupon = Coupon(
                id=cpn_data["id"],
                code=cpn_data["code"],
                discount_pct=cpn_data["discount_pct"],
                max_uses=cpn_data["max_uses"],
                times_used=cpn_data["times_used"],
                is_active=cpn_data["is_active"],
            )
            session.add(coupon)
            
    session.commit()
