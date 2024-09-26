// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

package com.connect.connectTheDots;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.web.bind.annotation.*;
import org.yaml.snakeyaml.Yaml;

@SpringBootApplication
@RestController
@RequestMapping(value="/")
public class ConnectTheDotsApplication extends SpringBootServletInitializer {

	@RequestMapping(value="/upload",method=RequestMethod.POST,produces="application/json")
	public Object ParseYaml(@RequestParam(value="yamlSpecification") String yamlSpecification) {
		try {
			Yaml yaml=new Yaml();
			Object obj=yaml.load(yamlSpecification);
			return obj;
		} catch(Exception e) {
			return e;
		}

	}
	public static void main(String[] args) {
		SpringApplication.run(ConnectTheDotsApplication.class, args);
	}

}