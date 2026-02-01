package com.railway.auth_service.dto.response.admin;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateAdminResponse {

  Long id;
  String name;
  String email;
  String userName;
}
