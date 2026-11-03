// Package httpx has the small HTTP helpers every package shares: the JSON
// error shape, request ids and the resolved client IP.
package httpx

import "github.com/gin-gonic/gin"

// Error aborts the request with the status and a {"error": msg} JSON body.
func Error(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"error": msg})
}
