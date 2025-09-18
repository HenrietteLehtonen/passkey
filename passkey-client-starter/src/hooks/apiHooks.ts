import fetchData from "@/lib/fetchData";
import { User } from "@sharedTypes/DBTypes";
import { LoginResponse, UserResponse } from "@sharedTypes/MessageTypes";
import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";
import {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/types";

const useUser = () => {
  // network functions for auth server user endpoints
  const getUserByToken = async (token: string) => {
    const options = {
      headers: {
        Authorization: "Bearer " + token,
      },
    };
    return await fetchData<UserResponse>(
      import.meta.env.VITE_AUTH_API + "/users/token/",
      options
    );
  };

  const getUsernameAvailable = async (username: string) => {
    return await fetchData<{ available: boolean }>(
      import.meta.env.VITE_AUTH_API + "/users/username/" + username
    );
  };

  const getEmailAvailable = async (email: string) => {
    return await fetchData<{ available: boolean }>(
      import.meta.env.VITE_AUTH_API + "/users/email/" + email
    );
  };

  return { getUserByToken, getUsernameAvailable, getEmailAvailable };
};

// usePasskey hook
const usePasskey = () => {
  // postUser function
  const postUser = async (
    // haetaan userista vaan username, password ja email
    user: Pick<User, "username" | "password" | "email">
  ) => {
    // Set up request options
    const options: RequestInit = {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(user),
    };

    // Fetch setup response
    const registrationResponse = await fetchData<{
      email: string;
      options: PublicKeyCredentialCreationOptionsJSON;
    }>(import.meta.env.VITE_PASSKEY_API + "/auth/setup", options);

    // Start registration process
    const attResp = await startRegistration(registrationResponse.options);

    // Prepare data for verification
    const data = {
      email: registrationResponse.email,
      registrationOptions: attResp,
    };

    // Fetch and return verification response
    const verifyOptions = {
      // ...options
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify(data),
    };
    return await fetchData<UserResponse>(
      import.meta.env.VITE_PASSKEY_API + "auth/verify",
      verifyOptions
    );
  };
  // Define postLogin function
  const postLogin = async (email: string) => {
    // Fetch login setup options
    const loginOptions = {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email: email }),
    };
    const authenticationResponse =
      await fetchData<PublicKeyCredentialRequestOptionsJSON>(
        import.meta.env.VITE_PASSKEY_API + "/auth/login-setup",
        loginOptions
      );

    // Start authentication process
    const attResp = await startAuthentication(authenticationResponse);

    // Fetch and return login verification response
    const verifyOptions = {
      ...loginOptions,
      body: JSON.stringify({ email, authResponse: attResp }),
    };

    return await fetchData<LoginResponse>(
      import.meta.env.VITE_PASSKEY_API + "/auth/login-verify",
      verifyOptions
    );
  };

  return { postUser, postLogin };
};

export { useUser, usePasskey };
