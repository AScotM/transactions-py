#!/usr/bin/env python3

import asyncio
import json
import random
import time
import uuid
import os
import re
import weakref
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
import logging
from functools import wraps
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')

def with_retry(max_retries: int = 3, delay: float = 0.1):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries and getattr(e, 'retryable', True):
                        await asyncio.sleep(delay * (2 ** attempt))
                        continue
                    raise
            raise last_exception
        return wrapper
    return decorator

@dataclass
class Config:
    base_failure_rate: float = 0.05
    max_retries: int = 2
    gateway_timeout: float = 30.0
    fraud_threshold: float = 0.7
    circuit_breaker_failures: int = 5
    circuit_breaker_reset: float = 60.0
    max_amount: float = 10000.0

    def __post_init__(self):
        self._validate()

    def _validate(self):
        if not 0 <= self.base_failure_rate <= 1:
            raise ValueError("base_failure_rate must be between 0 and 1")
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if self.gateway_timeout <= 0:
            raise ValueError("gateway_timeout must be positive")

    @classmethod
    def load_config(cls) -> 'Config':
        return cls(
            base_failure_rate=float(os.getenv('PAYMENT_BASE_FAILURE_RATE', '0.05')),
            max_retries=int(os.getenv('PAYMENT_MAX_RETRIES', '2')),
            gateway_timeout=float(os.getenv('PAYMENT_GATEWAY_TIMEOUT', '30.0')),
            fraud_threshold=float(os.getenv('PAYMENT_FRAUD_THRESHOLD', '0.7')),
            circuit_breaker_failures=int(os.getenv('CIRCUIT_BREAKER_FAILURES', '5')),
            circuit_breaker_reset=float(os.getenv('CIRCUIT_BREAKER_RESET', '60.0')),
            max_amount=float(os.getenv('PAYMENT_MAX_AMOUNT', '10000.0'))
        )

class PaymentError(Exception):
    def __init__(self, code: str, message: str, payment_id: str = "", retryable: bool = True):
        self.code = code
        self.message = message
        self.payment_id = payment_id
        self.retryable = retryable
        self.timestamp = datetime.now()
        super().__init__(self.message)

    def __str__(self):
        return f"[{self.code}] {self.message} (payment: {self.payment_id})"

class PaymentErrors:
    FRAUD_DETECTED = PaymentError("FRAUD", "Transaction flagged as fraudulent", retryable=False)
    GATEWAY_TIMEOUT = PaymentError("GATEWAY_TIMEOUT", "Payment gateway timeout", retryable=True)
    INVALID_AMOUNT = PaymentError("INVALID_AMOUNT", "Amount must be positive", retryable=False)
    INVALID_CURRENCY = PaymentError("INVALID_CURRENCY", "Invalid currency", retryable=False)
    CIRCUIT_OPEN = PaymentError("CIRCUIT_OPEN", "Circuit breaker is open", retryable=True)
    
    @staticmethod
    def amount_too_high(max_amount: float) -> PaymentError:
        return PaymentError("AMOUNT_TOO_HIGH", 
                          f"Amount exceeds maximum allowed: {max_amount}", 
                          retryable=False)

@dataclass
class Payment:
    id: str
    amount: float
    currency: str
    merchant_id: str
    customer_id: str
    status: str = "pending"
    created_at: datetime = field(default_factory=datetime.now)
    processed_at: Optional[datetime] = None
    error_reason: str = ""
    retry_count: int = 0
    idempotency_key: str = ""

    def sanitize(self) -> None:
        self.merchant_id = re.sub(r'[^a-zA-Z0-9_-]', '', self.merchant_id)
        self.customer_id = re.sub(r'[^a-zA-Z0-9_-]', '', self.customer_id)
        self.currency = self.currency.upper().strip()
        self.amount = float(Decimal(str(self.amount)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP))

    def validate(self) -> None:
        self.sanitize()
        
        if self.amount <= 0:
            raise PaymentErrors.INVALID_AMOUNT
        
        if abs(self.amount - round(self.amount, 2)) > 0.001:
            raise PaymentError("INVALID_AMOUNT_PRECISION", 
                             "Amount must have at most 2 decimal places", 
                             retryable=False)
        
        valid_currencies = {"USD", "EUR", "GBP", "CAD"}
        if self.currency not in valid_currencies:
            raise PaymentErrors.INVALID_CURRENCY
        
        if not self.merchant_id or not re.match(r'^[a-zA-Z0-9_-]+$', self.merchant_id):
            raise PaymentError("INVALID_MERCHANT", 
                             "Merchant ID is required and must be alphanumeric", 
                             retryable=False)
        
        if not self.customer_id or not re.match(r'^[a-zA-Z0-9_-]+$', self.customer_id):
            raise PaymentError("INVALID_CUSTOMER", 
                             "Customer ID is required and must be alphanumeric", 
                             retryable=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "amount": self.amount,
            "currency": self.currency,
            "merchant_id": self.merchant_id,
            "customer_id": self.customer_id,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
            "error_reason": self.error_reason,
            "retry_count": self.retry_count,
            "idempotency_key": self.idempotency_key
        }

@dataclass
class PaymentGateway:
    name: str
    success_rate: float
    latency: float
    is_active: bool = True

@dataclass
class FraudDetectionResult:
    is_fraudulent: bool
    risk_score: float
    reasons: List[str] = field(default_factory=list)

class CircuitBreakerState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    def __init__(self, max_failures: int, reset_timeout: float, half_open_max_requests: int = 3):
        self.max_failures = max_failures
        self.reset_timeout = reset_timeout
        self.half_open_max_requests = half_open_max_requests
        self.half_open_attempts = 0
        self.failures = 0
        self.last_failure: Optional[float] = None

    async def allow(self) -> bool:
        state = await self.state()
        if state == CircuitBreakerState.OPEN:
            return False
        elif state == CircuitBreakerState.HALF_OPEN:
            if self.half_open_attempts >= self.half_open_max_requests:
                return False
            self.half_open_attempts += 1
        return True

    async def record_success(self) -> None:
        self.failures = 0
        self.half_open_attempts = 0
        self.last_failure = None

    async def record_failure(self) -> None:
        self.failures += 1
        self.last_failure = time.time()

    async def state(self) -> CircuitBreakerState:
        if self.failures >= self.max_failures:
            if self.last_failure and (time.time() - self.last_failure) > self.reset_timeout:
                return CircuitBreakerState.HALF_OPEN
            return CircuitBreakerState.OPEN
        return CircuitBreakerState.CLOSED

@dataclass
class PaymentMetrics:
    total_processed: int = 0
    successful: int = 0
    failed: int = 0
    fraud_detected: int = 0
    total_amount: float = 0.0
    average_processing_time: float = 0.0
    success_rate: float = 0.0
    circuit_breaker_trips: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_processed": self.total_processed,
            "successful": self.successful,
            "failed": self.failed,
            "fraud_detected": self.fraud_detected,
            "total_amount": self.total_amount,
            "average_processing_time": self.average_processing_time,
            "success_rate": self.success_rate,
            "circuit_breaker_trips": self.circuit_breaker_trips
        }

class PaymentProcessor:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config.load_config()
        
        self.gateways = [
            PaymentGateway("Stripe", 0.98, 0.2),
            PaymentGateway("PayPal", 0.96, 0.3),
            PaymentGateway("Square", 0.97, 0.25),
            PaymentGateway("Adyen", 0.99, 0.15),
        ]
        
        self.fraud_service = FraudDetectionService(self.config)
        self.chaos_injector = ChaosInjector(self.config)
        
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.transaction_history: Dict[str, weakref.ref[Payment]] = {}
        self.idempotency_store: Dict[str, weakref.ref[Payment]] = {}
        self.metrics = PaymentMetrics()
        
        for gateway in self.gateways:
            self.circuit_breakers[gateway.name] = CircuitBreaker(
                self.config.circuit_breaker_failures,
                self.config.circuit_breaker_reset
            )

    async def process_payment(self, amount: float, currency: str, 
                            merchant_id: str, customer_id: str) -> Payment:
        return await self.process_payment_with_context(
            amount, currency, merchant_id, customer_id, ""
        )

    async def process_payment_with_context(self, amount: float, currency: str,
                                         merchant_id: str, customer_id: str,
                                         idempotency_key: str) -> Payment:
        if idempotency_key and idempotency_key in self.idempotency_store:
            existing_payment_ref = self.idempotency_store[idempotency_key]
            existing_payment = existing_payment_ref()
            if existing_payment:
                logger.info(f"Returning existing payment for idempotency key: {idempotency_key}")
                return existing_payment

        start_time = time.time()

        payment = Payment(
            id=self._generate_payment_id(),
            amount=amount,
            currency=currency,
            merchant_id=merchant_id,
            customer_id=customer_id,
            idempotency_key=idempotency_key
        )

        try:
            payment.validate()
            
            if self.config.max_amount > 0 and payment.amount > self.config.max_amount:
                raise PaymentErrors.amount_too_high(self.config.max_amount)
                
        except PaymentError as e:
            return await self._handle_payment_failure(payment, e, start_time)

        payment_ref = weakref.ref(payment)
        self.transaction_history[payment.id] = payment_ref
        if idempotency_key:
            self.idempotency_store[idempotency_key] = payment_ref

        logger.info(f"Processing payment {payment.id}: ${amount:.2f} from {customer_id} to {merchant_id}")

        try:
            fraud_result = await self.fraud_service.check_payment(payment)
            if fraud_result.is_fraudulent:
                self.metrics.fraud_detected += 1
                fraud_error = PaymentError(
                    "FRAUD_DETECTED",
                    f"Fraud detected: {', '.join(fraud_result.reasons)}",
                    payment.id,
                    False
                )
                return await self._handle_payment_failure(payment, fraud_error, start_time)

            await self.chaos_injector.inject_payment_chaos(payment)

            gateway = await self._select_payment_gateway()
            
            circuit_breaker = self.circuit_breakers[gateway.name]
            if not await circuit_breaker.allow():
                circuit_error = PaymentError(
                    "CIRCUIT_BREAKER_OPEN",
                    f"Gateway {gateway.name} circuit breaker is open",
                    payment.id,
                    True
                )
                return await self._handle_payment_failure(payment, circuit_error, start_time)

            payment.status = "processing"

            success, process_error = await self._process_with_gateway(payment, gateway)
            
            if process_error:
                await circuit_breaker.record_failure()
                self.metrics.circuit_breaker_trips += 1
                return await self._handle_payment_failure(payment, process_error, start_time)

            if not success:
                if payment.retry_count < self.config.max_retries:
                    payment.retry_count += 1
                    logger.info(f"Retrying payment {payment.id} (attempt {payment.retry_count})")
                    success, _ = await self._process_with_gateway(payment, gateway)

            if success:
                await circuit_breaker.record_success()
                return await self._handle_payment_success(payment, gateway.name, start_time)
            else:
                await circuit_breaker.record_failure()
                self.metrics.circuit_breaker_trips += 1
                gateway_error = PaymentError(
                    "GATEWAY_FAILURE",
                    "All payment attempts failed",
                    payment.id,
                    True
                )
                return await self._handle_payment_failure(payment, gateway_error, start_time)

        except Exception as e:
            if not isinstance(e, PaymentError):
                e = PaymentError("UNEXPECTED_ERROR", str(e), payment.id, True)
            return await self._handle_payment_failure(payment, e, start_time)

    @with_retry(max_retries=2)
    async def _process_with_gateway(self, payment: Payment, gateway: PaymentGateway) -> Tuple[bool, Optional[PaymentError]]:
        try:
            processing_time = gateway.latency + random.uniform(0, 0.1)
            
            try:
                await asyncio.wait_for(
                    asyncio.sleep(processing_time),
                    timeout=self.config.gateway_timeout
                )
            except asyncio.TimeoutError:
                return False, PaymentErrors.GATEWAY_TIMEOUT

            success_threshold = gateway.success_rate * self.chaos_injector.get_success_rate_modifier()
            success = random.random() <= success_threshold
            
            return success, None

        except asyncio.TimeoutError:
            return False, PaymentErrors.GATEWAY_TIMEOUT
        except Exception as e:
            return False, PaymentError("GATEWAY_ERROR", str(e), payment.id, True)

    async def _select_payment_gateway(self) -> PaymentGateway:
        active_gateways = []
        for gateway in self.gateways:
            if gateway.is_active:
                state = await self.circuit_breakers[gateway.name].state()
                if state != CircuitBreakerState.OPEN:
                    active_gateways.append(gateway)

        if not active_gateways:
            logger.warning("No active gateways available, using fallback")
            return self.gateways[0]

        return random.choice(active_gateways)

    async def _handle_payment_success(self, payment: Payment, gateway: str, start_time: float) -> Payment:
        processing_time = time.time() - start_time

        payment.status = "completed"
        payment.processed_at = datetime.now()

        self.metrics.successful += 1
        self.metrics.total_processed += 1
        self.metrics.total_amount += payment.amount

        if self.metrics.successful == 1:
            self.metrics.average_processing_time = processing_time
        else:
            self.metrics.average_processing_time = (
                (self.metrics.average_processing_time * (self.metrics.successful - 1) + processing_time) 
                / self.metrics.successful
            )

        if self.metrics.total_processed > 0:
            self.metrics.success_rate = self.metrics.successful / self.metrics.total_processed
        else:
            self.metrics.success_rate = 0.0

        logger.info(f"Payment {payment.id} completed successfully via {gateway} (took {processing_time:.3f}s)")
        return payment

    async def _handle_payment_failure(self, payment: Payment, error: PaymentError, start_time: float) -> Payment:
        payment.status = "failed"
        payment.error_reason = str(error)
        payment.processed_at = datetime.now()

        self.metrics.failed += 1
        self.metrics.total_processed += 1
        
        if self.metrics.total_processed > 0:
            self.metrics.success_rate = self.metrics.successful / self.metrics.total_processed
        else:
            self.metrics.success_rate = 0.0

        logger.warning(f"Payment {payment.id} failed: {error}")
        return payment

    def _generate_payment_id(self) -> str:
        import secrets
        timestamp = int(time.time() * 1000)
        random_part = secrets.randbelow(10000)
        return f"pay_{timestamp}_{random_part:04d}"

    async def cleanup_old_payments(self, max_age_hours: int = 24):
        cutoff_time = datetime.now().timestamp() - (max_age_hours * 3600)
        to_remove = []
        
        for payment_id, payment_ref in self.transaction_history.items():
            payment = payment_ref()
            if payment and payment.created_at.timestamp() < cutoff_time:
                to_remove.append(payment_id)
        
        for payment_id in to_remove:
            del self.transaction_history[payment_id]
        
        logger.info(f"Cleaned up {len(to_remove)} old payments")

    async def generate_business_report(self) -> Dict[str, Any]:
        logger.info("Generating business report...")
        
        revenue_by_merchant: Dict[str, float] = {}
        circuit_states: Dict[str, str] = {}

        for payment_ref in self.transaction_history.values():
            payment = payment_ref()
            if payment and payment.status == "completed":
                revenue_by_merchant[payment.merchant_id] = revenue_by_merchant.get(payment.merchant_id, 0.0) + payment.amount

        for gateway_name, circuit_breaker in self.circuit_breakers.items():
            state = await circuit_breaker.state()
            circuit_states[gateway_name] = state.value

        report = {
            "metrics": self.metrics.to_dict(),
            "revenue_by_merchant": revenue_by_merchant,
            "circuit_breaker_states": circuit_states,
            "total_transactions": len(self.transaction_history),
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info("Business report generated successfully")
        return report

    async def save_report_to_file(self, filename: str) -> None:
        report = await self.generate_business_report()
        
        os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else '.', exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Report saved to {filename}")

class FraudDetectionService:
    def __init__(self, config: Config):
        self.config = config
        self.risk_patterns = [
            "high_amount_velocity",
            "unusual_geolocation",
            "suspicious_device",
            "risky_merchant_category",
            "card_testing_pattern",
        ]

    async def check_payment(self, payment: Payment) -> FraudDetectionResult:
        await asyncio.sleep(0.05)

        risk_score = random.random()
        reasons = []

        if payment.amount > 1000:
            risk_score += 0.3
            reasons.append("high_amount")

        if random.random() < 0.1:
            pattern = random.choice(self.risk_patterns)
            reasons.append(pattern)
            risk_score += 0.4

        risk_score = min(max(risk_score, 0.0), 1.0)
        is_fraudulent = risk_score > self.config.fraud_threshold

        return FraudDetectionResult(is_fraudulent, risk_score, reasons)

class ChaosInjector:
    def __init__(self, config: Config):
        self.config = config
        self.failure_rate = config.base_failure_rate
        self.latency_range = 2.0
        self.gateway_outages: Dict[str, bool] = {}

    async def inject_payment_chaos(self, payment: Payment) -> None:
        if random.random() < 0.02:
            gateway = "Stripe" if random.random() < 0.5 else "PayPal"
            self.gateway_outages[gateway] = True
            logger.warning(f"Simulating gateway outage: {gateway}")

        if random.random() < 0.03:
            latency = random.uniform(0, self.latency_range)
            await asyncio.sleep(latency)
            logger.info(f"Injected latency: {latency:.3f}s")

    def get_success_rate_modifier(self) -> float:
        modifier = 1.0
        outages = len(self.gateway_outages)
        if outages > 0:
            modifier -= 0.1 * outages
        return max(modifier, 0.0)

async def process_single_transaction(processor: PaymentProcessor, transaction_num: int,
                                   merchants: List[str], customers: List[str]) -> None:
    try:
        amount = 10 + random.randint(0, 500)
        merchant = random.choice(merchants)
        customer = random.choice(customers)
        idempotency_key = f"txn_{transaction_num}_{int(time.time())}"

        payment = await processor.process_payment_with_context(
            amount, "USD", merchant, customer, idempotency_key
        )

        if payment.status == "completed":
            print(f"Transaction {transaction_num} successful: {payment.id} ${payment.amount:.2f}")
        else:
            print(f"Transaction {transaction_num} failed: {payment.error_reason}")

    except Exception as e:
        print(f"Transaction {transaction_num} failed with exception: {e}")

async def main():
    try:
        print("Enhanced Payment Processing System with Chaos Engineering - Python Version")
        print("=" * 80)

        config = Config.load_config()
        processor = PaymentProcessor(config)

        merchants = ["amazon", "netflix", "spotify", "uber", "starbucks"]
        customers = ["cust_001", "cust_002", "cust_003", "cust_004", "cust_005"]

        print("\nProcessing payments...")

        successful = 0
        failed = 0

        for i in range(25):
            try:
                amount = 10 + random.randint(0, 500)
                merchant = random.choice(merchants)
                customer = random.choice(customers)
                idempotency_key = f"txn_{i}_{int(time.time())}"

                payment = await processor.process_payment_with_context(
                    amount, "USD", merchant, customer, idempotency_key
                )

                if payment.status == "completed":
                    print(f"Transaction {i} successful: {payment.id} ${payment.amount:.2f}")
                    successful += 1
                else:
                    print(f"Transaction {i} failed: {payment.error_reason}")
                    failed += 1

                await asyncio.sleep(0.1)

            except Exception as e:
                print(f"Transaction {i} failed with exception: {e}")
                failed += 1

        print(f"\nCompleted {successful} successful transactions, {failed} failed")

        print("\nGenerating Enhanced Business Report...")
        print("=" * 50)

        report = await processor.generate_business_report()
        metrics = report["metrics"]
        circuit_states = report["circuit_breaker_states"]

        print(f"Total Processed: {metrics['total_processed']}")
        print(f"Successful: {metrics['successful']}")
        print(f"Failed: {metrics['failed']}")
        print(f"Fraud Detected: {metrics['fraud_detected']}")
        print(f"Circuit Breaker Trips: {metrics['circuit_breaker_trips']}")
        print(f"Success Rate: {metrics['success_rate']:.2%}")
        print(f"Total Amount Processed: ${metrics['total_amount']:.2f}")
        print(f"Average Processing Time: {metrics['average_processing_time']:.3f}s")

        print("\nCircuit Breaker States:")
        for gateway, state in circuit_states.items():
            print(f"  {gateway}: {state}")

        try:
            await processor.save_report_to_file("enhanced_payment_report_python.json")
            print("\nDetailed report saved to enhanced_payment_report_python.json")
        except Exception as e:
            print(f"\nError saving report: {e}")

        print("\nEnhanced Chaos Resilience Analysis:")
        print("=" * 40)
        print(f"System handled {metrics['success_rate']:.1%} success rate under chaos conditions")
        print(f"Detected and prevented {metrics['fraud_detected']} fraudulent transactions")
        print(f"Circuit breakers prevented {metrics['circuit_breaker_trips']} potential cascade failures")
        print(f"Processed ${metrics['total_amount']:.2f} in total transaction volume")
        print(f"Average processing time: {metrics['average_processing_time']:.3f}s")
        
        print("\nSystem Configuration:")
        print(f"Max Retries: {config.max_retries}")
        print(f"Fraud Threshold: {config.fraud_threshold}")
        print(f"Max Amount: ${config.max_amount:.2f}")
        print(f"Circuit Breaker: {config.circuit_breaker_failures} failures / {config.circuit_breaker_reset}s reset")

    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )
    exit_code = asyncio.run(main())
    exit(exit_code)
