// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

package com.connect.connectTheDots;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ConnectTheDotsView {

    @GetMapping(value="/")
    public String yamlPage() {
        return "yamlpage";
    }
    
}
