-- Synthetic support tickets for the local demo. Names, phones, and SSN-like values are fake.

CREATE TABLE tickets (
    id integer PRIMARY KEY,
    opened_at text NOT NULL,
    priority text,
    channel text,
    subject text,
    body text
);

INSERT INTO tickets (id, opened_at, priority, channel, subject, body) VALUES
    (501, '2024-10-01', 'high', 'email', 'Torn sleeve', 'Customer mina.ortiz@northwind.example asked for a repair.'),
    (502, '2024-10-02', 'low', 'chat', 'Hours', 'What time does the shop close?'),
    (503, '2024-10-03', 'medium', 'phone', 'Callback', 'Please call 503-555-0148 about the alteration.'),
    (504, '2024-10-04', NULL, 'web', 'Status', 'Any update on order 4412?'),
    (505, '2024-10-05', 'high', 'email', 'Invoice', 'The form showed 412-77-9012 and the customer objected.'),
    (506, '2024-10-06', 'low', 'chat', 'Color', 'Is the wool coat still in stock?'),
    (507, '2024-10-07', 'medium', 'email', 'Exchange', 'Ship the replacement to renee.cho@northwind.example.'),
    (508, '2024-10-08', 'high', 'web', 'Repeat', 'This is the third time the hem failed.');
