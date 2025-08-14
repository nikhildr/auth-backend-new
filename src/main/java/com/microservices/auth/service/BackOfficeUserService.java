package com.microservices.auth.service;


import com.microservices.auth.entity.BackOfficeUser;
import com.microservices.auth.repository.BackOfficeRepository;
import com.microservices.auth.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class BackOfficeUserService {

    private final BackOfficeRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    // private final EmailService emailService;

    public BackOfficeUser createUser(BackOfficeUser user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        BackOfficeUser savedUser = userRepository.save(user);

        // Send notification email
        //   emailService.sendEmail(savedUser.getEmail(), savedUser.getUsername());

        return savedUser;
    }

    public boolean resetPassword(String username, String newPassword) {
        Optional<BackOfficeUser> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            BackOfficeUser user = userOpt.get();
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            return true;
        }
        return false;
    }

    public Optional<BackOfficeUser> updateUser(Long id, BackOfficeUser updatedUser) {
        return userRepository.findById(id).map(user -> {
            user.setUsername(updatedUser.getUsername());
            user.setEmail(updatedUser.getEmail());
            user.setPhone(updatedUser.getPhone());
            user.setRoles(updatedUser.getRoles());
            user.setBankCode(updatedUser.getBankCode());
            user.setFlexFld1(updatedUser.getFlexFld1());
            user.setFlexFld2(updatedUser.getFlexFld2());
            return userRepository.save(user);
        });
    }

    public boolean deleteUser(Long id) {
        return userRepository.findById(id).map(user -> {
            userRepository.delete(user);
            return true;
        }).orElse(false);
    }

    public Optional<BackOfficeUser> getUserById(Long id) {
        return userRepository.findById(id);
    }


    public List<BackOfficeUser> getAllUsers() {
        return userRepository.findAll();
    }

    @Transactional
    public UserDetails loadUserById(Long id) {
        BackOfficeUser user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));

        return UserPrincipal.create(user);
    }

}