const express = require("express");

const app = express();
const PORT = 3000;


app.disable("x-powered-by");
app.use(express.json());


const userTable = [
  { id: 1, name: "Alice", role: "customer", department: "north" },
  { id: 2, name: "Bob", role: "customer", department: "south" },
  { id: 3, name: "Charlie", role: "support", department: "north" },
];

const orderTable = [
  { id: 1, userId: 1, item: "Laptop", region: "north", total: 2000 },
  { id: 2, userId: 1, item: "Mouse", region: "north", total: 40 },
  { id: 3, userId: 2, item: "Monitor", region: "south", total: 300 },
  { id: 4, userId: 2, item: "Keyboard", region: "south", total: 60 },
];


function requireUser(req, res, next) {
  const rawId = req.get("X-User-Id");
  const parsedId = Number(rawId);

  if (!parsedId) {
    return res.status(401).json({ error: "Missing or invalid X-User-Id header" });
  }

  const currentUser = userTable.find((u) => u.id === parsedId);

  if (!currentUser) {
    return res.status(401).json({ error: "User not recognized" });
  }

  req.user = currentUser;
  next();
}


app.use(requireUser);


app.get("/", (req, res) => {
  res.json({
    api: "Access Control Demo",
    authenticatedAs: req.user,
  });
});


app.get("/orders/:id", (req, res) => {
  const orderId = Number(req.params.id);

  if (!Number.isInteger(orderId)) {
    return res.status(400).json({ error: "Invalid order ID" });
  }

  const order = orderTable.find((o) => o.id === orderId);

  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }

  if (order.userId !== req.user.id) {
    return res.status(403).json({ error: "Access denied to this order" });
  }

  res.json(order);
});


app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
