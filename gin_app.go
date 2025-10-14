package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    
    r.GET("/ping", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "message": "pong",
        })
    })
    
    r.POST("/users", func(c *gin.Context) {
        c.JSON(201, gin.H{})
    })
    
    r.PUT("/users/:id", func(c *gin.Context) {
        c.JSON(200, gin.H{})
    })
    
    r.DELETE("/users/:id", func(c *gin.Context) {
        c.JSON(204, gin.H{})
    })
    
    r.Run()
}