package com.lww.springboot_vue_demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;

/**
 *
 * @author lww
 */
@SpringBootApplication
public class LittleNoteApplication {

    public static void main(String[] args) {
        SpringApplication.run(LittleNoteApplication.class, args);
    }

}
