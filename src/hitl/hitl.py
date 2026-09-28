"""
Lab 11 — Optional enrichment: Human-in-the-Loop Design
  (Không chấm — tham khảo. Tóm tắt nộp do scripts/grade.py tự sinh,
   không viết report/*.md tay.)
  - Confidence Router
  - 3 HITL decision points
"""
from dataclasses import dataclass


# ============================================================
# Optional enrichment: ConfidenceRouter (không chấm)
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # Optional: Implement routing logic
        #
        # 1. Check if action_type is in HIGH_RISK_ACTIONS
        #    -> If yes: always escalate (action="escalate", priority="high",
        #       requires_human=True, reason="High-risk action: {action_type}")
        #
        # 2. Check confidence thresholds:
        #    - confidence >= 0.9:
        #      action="auto_send", priority="low",
        #      requires_human=False, reason="High confidence"
        #
        #    - 0.7 <= confidence < 0.9:
        #      action="queue_review", priority="normal",
        #      requires_human=True, reason="Medium confidence — needs review"
        #
        #    - confidence < 0.7:
        #      action="escalate", priority="high",
        #      requires_human=True, reason="Low confidence — escalating"

        if task_type in self.high_risk_tasks:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High risk task type: {task_type}",
                priority="critical",
                requires_human=True,
            )

        if confidence >= 0.9:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence — automated response",
                priority="low",
                requires_human=False,
            )
        elif confidence >= 0.7:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )
        else:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason="Low confidence — escalating",
                priority="high",
                requires_human=True,
            )


# ============================================================
# Optional enrichment: 3 HITL decision points
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "High-Value Wire Transfer Approval",
        "trigger": "Transaction amount exceeds 100,000,000 VND or unusual beneficiary account",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Source account, destination account, transaction history, customer risk score, device fingerprint",
        "example": "Customer requests 500,000,000 VND wire transfer to a newly added offshore beneficiary",
        "approval_path": "Approve: execute transaction via core banking API; Reject: cancel transfer and alert fraud team; Timeout: pause transfer and request OTP/call confirmation",
        "audit_fields": "correlation_id, customer_id, proposed_action, transfer_amount, destination_iban, reviewer_id, timestamp",
    },
    {
        "id": 2,
        "name": "Account Closure and Sensitive Profile Modification",
        "trigger": "Request to close account, reset 2FA, or change registered national ID (CCCD)",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Customer KYC records, photo ID comparison, reason for modification, account status",
        "example": "Customer requests changing phone number and registered email while balance is >50M VND",
        "approval_path": "Approve: update profile in CRM; Reject: retain current contact info; Timeout: escalate to branch officer callback",
        "audit_fields": "correlation_id, customer_id, change_diff, verification_evidence, officer_decision, timestamp",
    },
    {
        "id": 3,
        "name": "Disputed Credit Card Chargeback / Loan Modification",
        "trigger": "Customer disputes transaction over 5,000,000 VND or requests loan restructuring",
        "hitl_model": "human-on-the-loop",
        "context_needed": "Merchant transaction log, customer dispute claim statement, past dispute rate",
        "example": "Customer reports unrecognised international online transaction from merchant X",
        "approval_path": "Approve: issue temporary credit and initiate chargeback; Reject: provide merchant proof of delivery; Timeout: hold in queue for supervisor review within 24h",
        "audit_fields": "correlation_id, transaction_id, claim_details, merchant_code, reviewer_id, review_timestamp",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
