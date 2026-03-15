import express from "express";

const app = express();
app.use(express.json());
app.use(express.static("public"));

app.post("/api/login", async (req, res) => {
  try {
    const TENANT = "trial0195-id";
    const EMAIL = "agent.qiscus1@qisc.us";
    const PASSWORD = "Semuabisa123!";

    const response = await fetch(
      `https://${TENANT}.miitel.jp/api/auth/v2/authenticate`,
      {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          flow: "TENANT_USER_PASSWORD",
          params: {
            tenant_code: TENANT,
            email: EMAIL,
            password: PASSWORD,
          },
        }),
      }
    );

    const text = await response.text();
    console.log("Miitel API status:", response.status);
    console.log("Miitel API response:", text);

    if (!response.ok) {
      return res.status(response.status).send(text);
    }

    const data = JSON.parse(text);
    return res.json(data.auth_result);
  } catch (error) {
    console.error("Server error:", error);
    return res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => {
  console.log("Server running at http://localhost:3000");
});