package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/nayan-labs/zapauth/pkg/zapauth"
)

func main() {
	app := fiber.New(fiber.Config{
		AppName: "ZapAuth Example App",
	})

	// Public Route
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello! ZapAuth is running on port 3000. This is the consumer app on port 4000.")
	})

	// Protected Route
	// Assuming ZapAuth server runs with JWT_SECRET "super_secret_key_change_me"
	protected := app.Group("/api", zapauth.RequireAuth("super_secret_key_change_me"))

	protected.Get("/secret", func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		return c.JSON(fiber.Map{
			"message": "You are viewing highly classified information.",
			"user_id": userID,
		})
	})

	log.Println("Starting Example App on :4000")
	log.Fatal(app.Listen(":4000"))
}
