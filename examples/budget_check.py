"""Example check. The entry point name has to be the check id:

[project.entry-points."drs.checks"]
embedding_budget = "budget_check:EmbeddingBudgetCheck"
"""

from drs.context import ScanContext
from drs.sdk import Category, Finding, Outcome, Severity


class EmbeddingBudgetCheck:
    id = "embedding_budget"
    title = "Embedding budget"
    category = Category.DATA

    async def run(self, ctx: ScanContext) -> Outcome:
        budget = ctx.config.embedding.budget_usd
        if budget is None:
            return Outcome(
                summary="no embedding budget is configured",
                findings=[
                    Finding(
                        severity=Severity.MEDIUM,
                        title="Embedding spend is uncapped",
                        summary="embedding.budget_usd is not set, so a large corpus has no ceiling.",
                        remediation=(
                            "Set embedding.budget_usd to the amount the account owner will pay. "
                            "The document check compares its token estimate to that number."
                        ),
                    )
                ],
            )
        return Outcome(summary=f"embedding budget is ${budget:g}", stats={"budget_usd": budget})
