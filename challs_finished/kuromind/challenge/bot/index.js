const express = require("express");
const path = require("path");
const dotenv = require("dotenv");
const reviewBot = require("./review-bot.js");

dotenv.config({ path: path.join(__dirname, "../.env") });

const app = express();
const PORT = 1337;
const HOST = "127.0.0.1";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check
app.get("/health", (req, res) => {
    if (!process.env.OPERATOR_EMAIL || !process.env.OPERATOR_PASSWORD) {
        return res.status(400).json({
            error: "Operator credentials not configured in .env"
        });
        }
    return res.json({ status: "ok", message: "Review Bot Service is running" });
});

// Main review endpoint
app.post("/review", async (req, res) => {
  try {
    console.log("[Bot] Received review request");
    
    // Check if operator credentials are available
    if (!process.env.OPERATOR_EMAIL || !process.env.OPERATOR_PASSWORD) {
      return res.status(400).json({
        error: "Operator credentials not configured in .env"
      });
    }

    // Start the review bot
    const result = await reviewBot.runReviewBot({
      email: process.env.OPERATOR_EMAIL,
      password: process.env.OPERATOR_PASSWORD,
      appUrl: process.env.APP_URL || "http://127.0.0.1:80"
    });

    if (result.success) {
      return res.json({
        success: true,
        message: result.message,
        details: result.details
      });
    } else {
      return res.status(500).json({
        error: result.error || "Review process failed"
      });
    }
  } catch (error) {
    console.error("[Bot] Error:", error);
    res.status(500).json({
      error: "Internal server error",
      message: error.message
    });
  }
});

app.listen(PORT, HOST, () => {
  console.log(`\n=== Review Bot Service ===`);
  console.log(`Server running at http://${HOST}:${PORT}`);
  console.log(`Health check: http://${HOST}:${PORT}/health`);
  console.log(`Review endpoint: POST http://${HOST}:${PORT}/review`);
  console.log(`========================\n`);
});