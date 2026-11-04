"""Shared SQLAlchemy database models for ShopZone."""

from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash


class Base(DeclarativeBase):
    """Declarative base class for all ShopZone models."""
    pass


class User(Base):
    """User account entity."""
    
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    
    # Relationships
    tokens: Mapped[list["UserToken"]] = relationship("UserToken", back_populates="user", cascade="all, delete-orphan")
    cart_items: Mapped[list["CartItem"]] = relationship("CartItem", back_populates="user", cascade="all, delete-orphan")
    orders: Mapped[list["Order"]] = relationship("Order", back_populates="user", cascade="all, delete-orphan")
    
    def set_password(self, password: str) -> None:
        """Hash password using Werkzeug scrypt."""
        if not password or len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")
        self.password_hash = generate_password_hash(password, method="scrypt")
        
    def check_password(self, password: str) -> bool:
        """Verify password against stored scrypt hash."""
        if not self.password_hash or not password:
            return False
        return check_password_hash(self.password_hash, password)
        
    def to_dict(self) -> Dict[str, Any]:
        """Sanitized dictionary representation (never includes password_hash)."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class UserToken(Base):
    """Opaque UUID session token stored in database."""
    
    __tablename__ = "user_tokens"
    
    token: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    
    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="tokens")
    
    def is_valid(self) -> bool:
        """Check if token is active and not expired."""
        if self.is_revoked:
            return False
        # Normalize comparison to timezone-aware UTC
        now = datetime.now(timezone.utc)
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp > now


class Product(Base):
    """Product catalog item with authoritative server-side pricing in integer minor units.
    
    Inventory Design Note:
        Product stock is checked upon cart addition (`CartItem`), but is intentionally not
        depleted upon checkout. This preserves catalog state across repeated automated security
        invariant assessments (TC-01 through TC-07) without requiring restocking.
    """
    
    __tablename__ = "products"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    price_minor_units: Mapped[int] = mapped_column(Integer, nullable=False)  # Integer paise / cents
    stock: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "price_minor_units": self.price_minor_units,
            "stock": self.stock,
        }


class CartItem(Base):
    """Server-side shopping cart item."""
    
    __tablename__ = "cart_items"
    __table_args__ = (
        UniqueConstraint("user_id", "product_id", name="uq_cart_user_product"),
    )
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("products.id"), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    
    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="cart_items")
    product: Mapped["Product"] = relationship("Product")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "product_id": self.product_id,
            "product_name": self.product.name if self.product else None,
            "unit_price_minor_units": self.product.price_minor_units if self.product else 0,
            "quantity": self.quantity,
            "subtotal_minor_units": (self.product.price_minor_units * self.quantity) if self.product else 0,
        }


class Coupon(Base):
    """Discount coupon entity.
    
    Coupon Constraint Design:
        All promotional coupons in the FLOWGUARD ShopZone laboratory (CYBERSEC20, WELCOME10,
        STUDENT50) are globally single-use vouchers (`max_uses=1`). In secure mode, this global
        single-use invariant (BI-2) is enforced at the database level by the unique index
        `uq_coupon_global_redemption` on `coupon_redemptions(coupon_id)`. In vulnerable mode,
        this constraint is omitted to permit coupon replay and race exploitation (TC-02/TC-06).
    """
    
    __tablename__ = "coupons"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    discount_pct: Mapped[int] = mapped_column(Integer, nullable=False)  # e.g., 20 for 20%
    max_uses: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    times_used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    
    redemptions: Mapped[list["CouponRedemption"]] = relationship("CouponRedemption", back_populates="coupon")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "code": self.code,
            "discount_pct": self.discount_pct,
            "max_uses": self.max_uses,
            "times_used": self.times_used,
            "is_active": self.is_active,
        }


class CouponRedemption(Base):
    """Coupon redemption tracking."""
    
    __tablename__ = "coupon_redemptions"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    coupon_id: Mapped[int] = mapped_column(Integer, ForeignKey("coupons.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    order_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("orders.id"), nullable=True)
    redeemed_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    
    coupon: Mapped["Coupon"] = relationship("Coupon", back_populates="redemptions")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "coupon_id": self.coupon_id,
            "user_id": self.user_id,
            "order_id": self.order_id,
            "redeemed_at": self.redeemed_at.isoformat() if self.redeemed_at else None,
        }


class Order(Base):
    """Customer order state entity."""
    
    __tablename__ = "orders"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(32), default="CART", nullable=False, index=True
    )  # CART, PENDING_PAYMENT, PAID, CONFIRMED, CANCELLED
    total_minor_units: Mapped[int] = mapped_column(Integer, nullable=False)
    coupon_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("coupons.id"), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False
    )
    
    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="orders")
    items: Mapped[list["OrderItem"]] = relationship("OrderItem", back_populates="order", cascade="all, delete-orphan")
    payment: Mapped["Payment | None"] = relationship("Payment", back_populates="order", uselist=False)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "status": self.status,
            "total_minor_units": self.total_minor_units,
            "coupon_id": self.coupon_id,
            "idempotency_key": self.idempotency_key,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "items": [item.to_dict() for item in self.items] if self.items else [],
            "payment": self.payment.to_dict() if self.payment else None,
        }


class OrderItem(Base):
    """Order line item snapshot."""
    
    __tablename__ = "order_items"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    order_id: Mapped[int] = mapped_column(Integer, ForeignKey("orders.id", ondelete="CASCADE"), nullable=False)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("products.id"), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    unit_price_minor_units: Mapped[int] = mapped_column(Integer, nullable=False)
    
    order: Mapped["Order"] = relationship("Order", back_populates="items")
    product: Mapped["Product"] = relationship("Product")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "order_id": self.order_id,
            "product_id": self.product_id,
            "quantity": self.quantity,
            "unit_price_minor_units": self.unit_price_minor_units,
            "subtotal_minor_units": self.quantity * self.unit_price_minor_units,
        }


class Payment(Base):
    """Dummy payment ledger record."""
    
    __tablename__ = "payments"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    order_id: Mapped[int] = mapped_column(Integer, ForeignKey("orders.id"), unique=True, nullable=False)
    payment_ref: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    amount_minor_units: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False)  # PENDING, SUCCESS, FAILED
    processed_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    
    order: Mapped["Order"] = relationship("Order", back_populates="payment")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "order_id": self.order_id,
            "payment_ref": self.payment_ref,
            "amount_minor_units": self.amount_minor_units,
            "status": self.status,
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
        }
