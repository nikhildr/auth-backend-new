/*
package com.microservices.auth.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private  JavaMailSender mailSender;


    public void sendEmail(String to, String username) {
        SimpleMailMessage message = new SimpleMailMessage();



        String subject = "Welcome to BackOffice";
        String htmlBody = "<html><body>" +
                "<h2>Hello, " + username + "!</h2>" +
                "<p>Your account has been created successfully.</p>" +
                "<p>Login and start using the portal now.</p>" +
                "<hr>" +
                "<p style='font-size:12px;color:gray'>This is an automated email, do not reply.</p>" +
                "</body></html>";
        message.setTo(to);
        message.setSubject(subject);
        message.setText(htmlBody);
        message.setFrom("digivastllp@gmail.com"); // Replace with your email
        mailSender.send(message);
    }
}
*/
