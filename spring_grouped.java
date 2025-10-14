package com.example.demo;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/v1")
public class UserController {

    private RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/users")
    public List<User> getUsers() {
        // External API call
        String response = restTemplate.getForObject("https://jsonplaceholder.typicode.com/users", String.class);
        return userService.findAll();
    }

    @PostMapping("/users")
    public User createUser(@RequestBody User user) {
        // Another external API call
        restTemplate.postForObject("https://api.external-service.com/validate", user, String.class);
        return userService.save(user);
    }

    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        return userService.findById(id);
    }

    // Nested grouping
    @GetMapping("/users/{id}/posts")
    public List<Post> getUserPosts(@PathVariable Long id) {
        return postService.findByUserId(id);
    }
}