package middleware

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
)

func NewLogger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		
		err := c.Next()
		
		log.Printf("[%s] %s - %v - Status: %d\n", c.Method(), c.Path(), time.Since(start), c.Response().StatusCode())
		
		return err
	}
}
