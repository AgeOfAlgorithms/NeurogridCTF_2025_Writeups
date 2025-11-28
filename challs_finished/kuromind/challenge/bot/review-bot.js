const { chromium } = require("playwright");
const path = require("path");
const fs = require("fs");

// Queue to ensure only one review process at a time
let isProcessing = false;
const processingQueue = [];

// Persistent browser and context
let persistentBrowser = null;
let persistentContext = null;

const STORAGE_PATH = path.join(__dirname, ".playwright-storage");
const STATE_FILE = path.join(STORAGE_PATH, "state.json");

/**
 * Sleep utility function
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Get random feedback message based on action
 */
function getRandomFeedback(action) {
  const goodReviewOptions = [
    "Content looks good. Well structured.",
    "Great submission. Approved.",
    "This appears to be valid and well-formatted.",
    "Excellent work. Ready for publication.",
    "Good quality content. Proceeding.",
    "High quality submission. Approved.",
    "Well-written content. Approved.",
    "Meets all requirements. Approved.",
    "Outstanding work. Approved.",
    "Thank you for the excellent submission."
  ];

  const badReviewOptions = [
    "Needs some revision before approval.",
    "Please revise and resubmit.",
    "Content does not meet standards.",
    "Requires additional context.",
    "Thank you for the submission. Feedback: needs clarity.",
    "Please address the issues mentioned.",
    "Content needs improvement before approval.",
    "Does not meet quality standards.",
    "Requires significant revisions.",
    "Please provide more details and clarity."
  ];

  if (action === "approve") {
    return goodReviewOptions[Math.floor(Math.random() * goodReviewOptions.length)];
  } else {
    return badReviewOptions[Math.floor(Math.random() * badReviewOptions.length)];
  }
}

/**
 * Get random action (approve or reject)
 */
function getRandomAction() {
  return Math.random() > 0.5 ? "approve" : "reject";
}

/**
 * Initialize persistent browser and context
 */
async function initializePersistentBrowser() {
  if (persistentBrowser && persistentContext) {
    return;
  }

  console.log("[Bot] Initializing persistent browser...");

  // Ensure storage directory exists
  if (!fs.existsSync(STORAGE_PATH)) {
    fs.mkdirSync(STORAGE_PATH, { recursive: true });
  }

  persistentBrowser = await chromium.launch({
    headless: true,
  });

  // Create context with persistent storage from file
  const contextOptions = {};
  if (fs.existsSync(STATE_FILE)) {
    console.log("[Bot] Loading saved session from file...");
    contextOptions.storageState = STATE_FILE;
  }

  persistentContext = await persistentBrowser.newContext(contextOptions);

  console.log("[Bot] Persistent browser initialized");
}

/**
 * Main review bot function
 */
async function runReviewBot(options) {
  const { email, password, appUrl } = options;

  // Add to queue if already processing
  if (isProcessing) {
    console.log(`[Bot] Another review is in progress. Adding to queue (Queue size: ${processingQueue.length + 1})`);
    return new Promise((resolve) => {
      processingQueue.push(() => {
        console.log(`[Bot] Processing queued request (Remaining in queue: ${processingQueue.length})`);
        performReview(email, password, appUrl).then(resolve);
      });
    });
  }

  console.log("[Bot] No other review in progress. Starting immediately...");
  return performReview(email, password, appUrl);
}

/**
 * Perform the actual review workflow
 */
async function performReview(email, password, appUrl) {
  isProcessing = true;
  let page = null;

  try {
    console.log("[Bot] Starting review process...");

    // Initialize persistent browser if needed
    await initializePersistentBrowser();

    // Create a new page from persistent context
    page = await persistentContext.newPage();

    // Set default timeout to 3 seconds for all actions
    page.setDefaultTimeout(3000);

    // Set viewport
    await page.setViewportSize({ width: 1280, height: 720 });

    // Step 1: Navigate to login
    console.log("[Bot] Step 1: Navigating to login page...");
    await page.goto(`${appUrl}/login`, {
      waitUntil: "load",
      timeout: 3000,
    });

    // Check if already logged in (redirected to dashboard)
    const currentUrl = page.url();
    if (currentUrl.includes("/operator/dashboard")) {
      console.log("[Bot] Already logged in via saved session, proceeding to dashboard...");
    } else {
      // Step 2: Perform login
      console.log("[Bot] Step 2: Logging in with operator credentials...");
      await page.fill('input[type="email"]', email, { timeout: 3000 });
      await page.fill('input[type="password"]', password, { timeout: 3000 });

      // Click login button
      await page.click('button[type="submit"]', { timeout: 3000 });

      const postLoginUrl = page.url();
      console.log("[Bot] Post-login URL:", postLoginUrl);
      
      if (
        !postLoginUrl.includes("/operator/dashboard") &&
        !postLoginUrl.includes("/user/dashboard") &&
        !postLoginUrl.includes("/admin/dashboard") &&
        !postLoginUrl.includes("/login")
      ) {
        return {
          success: false,
          error: `Login failed - unexpected redirect to: ${postLoginUrl}`,
        };
      }

      // If still on login page, credentials failed
      if (postLoginUrl.includes("/login")) {
        return {
          success: false,
          error: "Login failed - invalid credentials",
        };
      }

      console.log("[Bot] Login successful, redirected to:", postLoginUrl);

      // If not on operator dashboard, navigate there
      if (!postLoginUrl.includes("/operator/dashboard")) {
        console.log("[Bot] Navigating to operator dashboard...");
        await page.goto(`${appUrl}/operator/dashboard`, {
          waitUntil: "load",
          timeout: 3000,
        });
      }

      // Save storage state to file after successful login
      await persistentContext.storageState({ path: STATE_FILE });
      console.log("[Bot] Session saved to file");
    }

    // Step 3: Check for pending submissions
    console.log("[Bot] Step 3: Checking for pending submissions...");
    await sleep(500);

    // Check if "No pending submissions" message exists
    const noPendingMessage = await page.locator(
      'text=No pending submissions to review'
    ).count();
    if (noPendingMessage > 0) {
      console.log("[Bot] No pending submissions to review");
      return {
        success: true,
        message: "No pending submissions",
        details: "Dashboard shows no pending items to review",
      };
    }

    // Step 4: Find and click the last review button
    console.log("[Bot] Step 4: Finding review submission buttons...");

    // Get all review buttons
    const reviewButtons = await page.locator(
      'a.btn-primary[href*="/operator/review/"]'
    ).all();

    if (reviewButtons.length === 0) {
      return {
        success: false,
        error: "No review submission buttons found",
      };
    }

    console.log(`[Bot] Found ${reviewButtons.length} review button(s)`);

    // Click the last review button
    const lastButton = reviewButtons[reviewButtons.length - 1];
    const reviewUrl = await lastButton.getAttribute("href");
    console.log(`[Bot] Clicking review button for: ${reviewUrl}`);

    await lastButton.click({ timeout: 3000 });

    // Extract the review ID from URL
    const reviewId = reviewUrl.split("/").pop();
    console.log(`[Bot] Navigated to review page for ID: ${reviewId}`);

    // Step 5: Fill in review form
    console.log("[Bot] Step 5: Filling review form...");
    await sleep(300);

    // Generate random action first, then appropriate feedback
    const action = getRandomAction();
    const feedback = getRandomFeedback(action);

    console.log(`[Bot] Action: ${action}, Feedback: ${feedback}`);

    // Type feedback
    await page.fill('textarea[name="feedback"]', feedback, { timeout: 3000 });
    await sleep(300);

    // Step 6: Submit the review
    console.log(`[Bot] Step 6: Submitting review (${action})...`);

    // Find and click the appropriate button
    const buttonSelector =
      action === "approve"
        ? 'button[value="approve"]'
        : 'button[value="reject"]';

    await page.click(buttonSelector, { timeout: 3000 });

    console.log("[Bot] Review submitted successfully!");

    return {
      success: true,
      message: "Review completed successfully",
      details: {
        reviewId,
        action,
        feedback,
        timestamp: new Date().toISOString(),
      },
    };
  } catch (error) {
    console.error("[Bot] Error during review process:", error);
    return {
      success: false,
      error: `Review process failed: ${error.message}`,
    };
  } finally {
    // Close only the page, keep context and browser alive
    if (page) {
      try {
        await page.close();
      } catch (e) {
        console.error("[Bot] Error closing page:", e);
      }
    }

    isProcessing = false;

    // Process next in queue
    if (processingQueue.length > 0) {
      console.log(`[Bot] Review completed. Processing next in queue (${processingQueue.length} requests waiting)...`);
      const nextTask = processingQueue.shift();
      nextTask();
    } else {
      console.log("[Bot] Review completed. Queue is empty.");
    }
  }
}

module.exports = {
  runReviewBot,
};
