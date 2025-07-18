package com.example.gateway.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HomeController {
    
    @GetMapping("/")
    @ResponseBody
    public String home() {
        return "<!DOCTYPE html>" +
                "<html>" +
                "<head><title>SangSangPlus Gateway</title></head>" +
                "<body>" +
                "<h1>SangSangPlus Gateway Service</h1>" +
                "<p>Gateway is running successfully!</p>" +
                "<ul>" +
                "<li><a href='/api/health'>Health Check</a></li>" +
                "<li><a href='/swagger-ui/index.html'>API Documentation</a></li>" +
                "<li><a href='/api/auth/register'>Register</a></li>" +
                "<li><a href='/api/auth/login'>Login</a></li>" +
                "</ul>" +
                "</body>" +
                "</html>";
    }
    
    @GetMapping("/generate_204")
    @ResponseBody
    public String generate204() {
        return "";
    }
}