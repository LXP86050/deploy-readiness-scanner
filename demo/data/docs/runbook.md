# Embedding runbook

The nightly job reads the ticket export and this folder. Chunk at 512 tokens and send the batch to the configured model.

If the vector gateway is down, leave the batch on disk and retry. Do not fall back to a region outside the contract.

Contact the operations list at ops@northwind.example when a batch has been stuck for more than an hour.
The address is in this runbook on purpose so the scanner has a document hit to show.
