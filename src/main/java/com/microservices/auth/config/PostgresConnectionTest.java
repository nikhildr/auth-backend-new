package com.microservices.auth.config;import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class PostgresConnectionTest {
    public static void main(String[] args) {
        // PostgreSQL connection details
        String url = "jdbc:postgresql://5.189.146.42:5432/backoffice-service";
        String user = "postgres";
        String password = "Digivast@2025";

        // Load PostgreSQL JDBC Driver (optional in modern Java, but safe to include)
        try {
            Class.forName("org.postgresql.Driver");
        } catch (ClassNotFoundException e) {
            System.out.println("PostgreSQL JDBC Driver not found!");
            e.printStackTrace();
            return;
        }

        // Try connecting
        try (Connection conn = DriverManager.getConnection(url, user, password)) {
            if (conn != null) {
                System.out.println("✅ Connected to PostgreSQL successfully!");
            } else {
                System.out.println("❌ Failed to connect to PostgreSQL.");
            }
        } catch (SQLException e) {
            System.out.println("Connection error:");
            e.printStackTrace();
        }
    }
}
