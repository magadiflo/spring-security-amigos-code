package com.magadiflo.app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplateController {

    @GetMapping("/login")
    public String getLoginView() {
        return "login"; //login.html
    }

    @GetMapping("/courses")
    public String getCourses() {
        return "courses"; //courses.html
    }

}
