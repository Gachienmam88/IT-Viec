package com.example.demo.controller;

import java.util.List;

import org.springframework.http.HttpStatus;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.domain.User;
import com.example.demo.service.UserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;

@RestController
public class UserController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public UserController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/users/create")
    public ResponseEntity<User> createNewUser(@RequestBody User user) {
        String hashPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(hashPassword);
        User newUser = userService.handleCreateUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(newUser);
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable("id") long id) {
        userService.handleDeleteUser(id);
        return ResponseEntity.ok().body("Delete successfully !");
    }

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUser() {
        List<User> list = userService.getAllUser();
        return ResponseEntity.ok().body(list);
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<User> getSingleUser(@PathVariable("id") long id) {
        User user = userService.getSingleUser(id);
        return ResponseEntity.ok().body(user);
    }

    @PutMapping("/users/update")
    public ResponseEntity<User> updateUser(@RequestBody User user) {
        User updateduser = this.userService.handleUpdateUser(user);
        return ResponseEntity.ok().body(updateduser);
    }

}
