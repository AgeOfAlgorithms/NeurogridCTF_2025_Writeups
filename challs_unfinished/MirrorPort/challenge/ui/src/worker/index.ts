import { Hono } from "hono";
import { cors } from "hono/cors";
import { z } from "zod";
import { CreateListingSchema } from "@/shared/types";

type Bindings = {
  DB: D1Database;
  R2_BUCKET: R2Bucket;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use("*", cors());

// Get all listings
app.get("/api/listings", async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM listings ORDER BY created_at DESC"
    ).all();
    
    return c.json({ listings: results });
  } catch (error) {
    console.error("Failed to fetch listings:", error);
    return c.json({ error: "Failed to fetch listings" }, 500);
  }
});

// Get listings for specific user
app.get("/api/listings/my", async (c) => {
  const sellerName = c.req.query("seller_name");
  
  if (!sellerName) {
    return c.json({ error: "seller_name is required" }, 400);
  }

  try {
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM listings WHERE seller_name = ? ORDER BY created_at DESC"
    ).bind(sellerName).all();
    
    return c.json({ listings: results });
  } catch (error) {
    console.error("Failed to fetch user listings:", error);
    return c.json({ error: "Failed to fetch user listings" }, 500);
  }
});

// Create new listing
app.post("/api/listings", async (c) => {
  try {
    const body = await c.req.json();
    const validatedData = CreateListingSchema.parse(body);
    
    const { success, meta } = await c.env.DB.prepare(
      `INSERT INTO listings (seller_name, scroll_name, price, description, note, image_url, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`
    ).bind(
      validatedData.seller_name,
      validatedData.scroll_name,
      validatedData.price,
      validatedData.description || null,
      validatedData.note || null,
      validatedData.image_url || null
    ).run();

    if (!success) {
      return c.json({ error: "Failed to create listing" }, 500);
    }

    // Fetch the created listing
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM listings WHERE id = ?"
    ).bind(meta.last_row_id).all();

    return c.json(results[0], 201);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ error: "Invalid input", details: error.errors }, 400);
    }
    console.error("Failed to create listing:", error);
    return c.json({ error: "Failed to create listing" }, 500);
  }
});

// Get specific listing
app.get("/api/listings/:id", async (c) => {
  const id = c.req.param("id");
  
  try {
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM listings WHERE id = ?"
    ).bind(id).all();
    
    if (results.length === 0) {
      return c.json({ error: "Listing not found" }, 404);
    }
    
    return c.json(results[0]);
  } catch (error) {
    console.error("Failed to fetch listing:", error);
    return c.json({ error: "Failed to fetch listing" }, 500);
  }
});

// Delete listing
app.delete("/api/listings/:id", async (c) => {
  const id = c.req.param("id");
  const sellerName = c.req.query("seller_name");
  
  if (!sellerName) {
    return c.json({ error: "seller_name is required" }, 400);
  }

  try {
    // Verify the listing belongs to the seller
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM listings WHERE id = ? AND seller_name = ?"
    ).bind(id, sellerName).all();
    
    if (results.length === 0) {
      return c.json({ error: "Listing not found or unauthorized" }, 404);
    }

    // Delete the listing
    const { success } = await c.env.DB.prepare(
      "DELETE FROM listings WHERE id = ? AND seller_name = ?"
    ).bind(id, sellerName).run();

    if (!success) {
      return c.json({ error: "Failed to delete listing" }, 500);
    }

    return c.json({ success: true });
  } catch (error) {
    console.error("Failed to delete listing:", error);
    return c.json({ error: "Failed to delete listing" }, 500);
  }
});

// Upload image
app.post("/api/upload/image", async (c) => {
  try {
    const formData = await c.req.formData();
    const file = formData.get("image") as File;
    
    if (!file) {
      return c.json({ error: "No image file provided" }, 400);
    }

    // Generate unique filename
    const timestamp = Date.now();
    const randomString = Math.random().toString(36).substring(2, 15);
    const fileExtension = file.name.split('.').pop() || 'jpg';
    const filename = `listings/${timestamp}_${randomString}.${fileExtension}`;

    // Upload to R2
    await c.env.R2_BUCKET.put(filename, file.stream(), {
      httpMetadata: {
        contentType: file.type,
      },
    });

    return c.json({
      success: true,
      image_url: `/api/files/${filename}`,
      filename: filename,
    });
  } catch (error) {
    console.error("Failed to upload image:", error);
    return c.json({ error: "Failed to upload image" }, 500);
  }
});

// Serve files from R2
app.get("/api/files/:filename{.*}", async (c) => {
  const filename = c.req.param("filename");
  
  try {
    const object = await c.env.R2_BUCKET.get(filename);
    
    if (!object) {
      return c.json({ error: "File not found" }, 404);
    }

    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("etag", object.httpEtag);
    
    return c.body(object.body, { headers });
  } catch (error) {
    console.error("Failed to serve file:", error);
    return c.json({ error: "Failed to serve file" }, 500);
  }
});

// Get listing status (for processing check)
app.get("/api/listings/:id/status", async (c) => {
  const id = c.req.param("id");
  
  try {
    const { results } = await c.env.DB.prepare(
      "SELECT is_processed FROM listings WHERE id = ?"
    ).bind(id).all();
    
    if (results.length === 0) {
      return c.json({ error: "Listing not found" }, 404);
    }
    
    return c.json({ processed: Boolean(results[0].is_processed) });
  } catch (error) {
    console.error("Failed to fetch listing status:", error);
    return c.json({ error: "Failed to fetch listing status" }, 500);
  }
});

// Get processed note (placeholder for now)
app.get("/api/listings/:id/processed-note", async (c) => {
  const id = c.req.param("id");
  
  try {
    const { results } = await c.env.DB.prepare(
      "SELECT note FROM listings WHERE id = ?"
    ).bind(id).all();
    
    if (results.length === 0) {
      return c.json({ error: "Listing not found" }, 404);
    }
    
    // For now, just return the note as-is
    // In a full implementation, this would process URLs and cache content
    return c.json({ processed_note: results[0].note || "" });
  } catch (error) {
    console.error("Failed to fetch processed note:", error);
    return c.json({ error: "Failed to fetch processed note" }, 500);
  }
});

export default app;
