package vn.tayjava.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import vn.tayjava.dto.request.UserRequestDTO;
import vn.tayjava.dto.response.PageResponse;
import vn.tayjava.dto.response.UserDetailResponse;
import vn.tayjava.model.User;
import vn.tayjava.util.UserStatus;

import java.util.List;

public interface UserService {

    UserDetailsService userDetailsService();

    User getByUsername(String userName);

    long saveUser(UserRequestDTO request);

    void updateUser(long userId, UserRequestDTO request);

    void changeStatus(long userId, UserStatus status);

    void deleteUser(long userId);

    UserDetailResponse getUser(long userId);

    PageResponse<?> getAllUsers(int pageNo, int pageSize);

    List<String> findAllRolesByUserId(long userId);
}
