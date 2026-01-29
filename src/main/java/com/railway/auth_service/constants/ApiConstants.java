package com.railway.auth_service.constants;

public class ApiConstants {

  public static final String API_BASE = "/api";
  public static final String AUTH_BASE = API_BASE + "/auth";

  public static final String USER_SIGNUP_GET_OTP ="/user/signup/get-otp";
  public static final String USER_SIGNUP_OTP_VERIFY = "/user/signup/otp/verify";

  public static final String LOGIN_ADMIN = "/admin/login/by/email";

  public static final String REFRESH_ACCESS_TOKEN = "/refresh/access/token";
  public static final String VALIDATE_TOKEN = "/validate/token";

  public static final String LOGOUT_CURRENT_DEVICE = "/logout";
  public static final String LOGOUT_ALL_DEVICES = "logout/all/devices";

  public static final String ADMIN_PROFILE_GET = "/admin/profile";

  public static final String ADMIN_CREATE = "/new/admin/create";
  public static final String ADMIN_LIST = "/admin/list";
  public static final String ADMIN_UPDATE_STATUS = "/admin/update/status/{adminId}"; // Activate/deactivate
  public static final String ADMIN_UPDATE_ROLE = "/admin/role/update"; // Change permissions
  public static final String ADMIN_DELETE = "/admin/delete/{id}";


}

