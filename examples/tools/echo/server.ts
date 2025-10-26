import express from "express";

const app = express();
app.use(express.json());

app.get("/echo", (req, res) => {
  res.json({
    ok: true,
    message: "hello from echo",
    time: new Date().toISOString(),
    headers: Object.fromEntries(
      Object.entries(req.headers).slice(0, 12) // trim for demo
    ),
  });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`echo listening on :${port}`));
