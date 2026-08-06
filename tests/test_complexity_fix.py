import re
import ast

def _control_nesting_python(code: str) -> int:
    """Calculate maximum control-flow nesting depth in Python via AST."""
    try:
        tree = ast.parse(code)
    except Exception:
        return 0

    max_depth = 0

    def walk_node(node, current_depth):
        nonlocal max_depth
        is_control = isinstance(node, (ast.If, ast.For, ast.While, ast.Try, getattr(ast, 'Match', ())))
        new_depth = current_depth + 1 if isinstance(node, (ast.If, ast.For, ast.While)) else current_depth
        max_depth = max(max_depth, new_depth)
        for child in ast.iter_child_nodes(node):
            walk_node(child, new_depth)

    walk_node(tree, 0)
    return max_depth


def _control_nesting_java(code: str) -> int:
    """
    Calculate maximum control-flow nesting depth in Java.
    Only counts nested decision/loop structures: if, for, while, switch, do-while.
    Ignores structural blocks: class, method, try, catch, finally, try-with-resources.
    """
    cleaned = re.sub(r'//.*', '', code)
    cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL)
    
    # Tokenize words and braces
    tokens = re.findall(r'(\bif\b|\bfor\b|\bwhile\b|\bswitch\b|\bdo\b|\btry\b|\bcatch\b|\bfinally\b|\bclass\b|\binterface\b|\{|\})', cleaned)
    
    max_control_depth = 0
    block_stack = []
    pending_control = False
    
    for token in tokens:
        if token in ('if', 'for', 'while', 'switch', 'do'):
            pending_control = True
        elif token in ('try', 'catch', 'finally', 'class', 'interface'):
            pending_control = False
        elif token == '{':
            if pending_control:
                block_stack.append('control')
                pending_control = False
            else:
                block_stack.append('structural')
            
            control_count = block_stack.count('control')
            max_control_depth = max(max_control_depth, control_count)
        elif token == '}':
            if block_stack:
                block_stack.pop()
            pending_control = False
            
    return max_control_depth

# Test Java snippet with try-with-resources and while loop
java_code = """
package com.demo.service;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SecureUserService {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/appdb";

    public void printUser(String userId) {
        String sql = "SELECT id, name, email FROM users WHERE id = ?";
        try (Connection connection = DriverManager.getConnection(DB_URL, "app_user", System.getenv("DB_PASS"));
             PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
            
            preparedStatement.setString(1, userId);
            
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                while (resultSet.next()) {
                    String name = resultSet.getString("name");
                    System.out.println("Found user: " + name);
                }
            }
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
        }
    }
}
"""

print("Java control nesting depth:", _control_nesting_java(java_code))
