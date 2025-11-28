import z from "zod";

/**
 * Types shared between the client and server go here.
 */

export const ListingSchema = z.object({
  id: z.number(),
  seller_name: z.string(),
  scroll_name: z.string(),
  price: z.number(),
  description: z.string().nullable(),
  note: z.string().nullable(),
  image_url: z.string().nullable(),
  is_processed: z.boolean(),
  created_at: z.string(),
  updated_at: z.string(),
});

export type Listing = z.infer<typeof ListingSchema>;

export const CreateListingSchema = z.object({
  seller_name: z.string().min(1, "Seller name is required"),
  scroll_name: z.string().min(1, "Scroll name is required"),
  price: z.number().min(0, "Price must be positive"),
  description: z.string().optional(),
  note: z.string().optional(),
  image_url: z.string().optional(),
});

export type CreateListing = z.infer<typeof CreateListingSchema>;

export const ListingsResponseSchema = z.object({
  listings: z.array(ListingSchema),
});

export type ListingsResponse = z.infer<typeof ListingsResponseSchema>;

export const UploadResponseSchema = z.object({
  success: z.boolean(),
  image_url: z.string(),
  filename: z.string(),
});

export type UploadResponse = z.infer<typeof UploadResponseSchema>;
