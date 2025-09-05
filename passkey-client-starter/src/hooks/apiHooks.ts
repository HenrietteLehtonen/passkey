import fetchData from "@/lib/fetchData";
import { User } from "@sharedTypes/DBTypes";
import { LoginResponse, UserResponse } from "@sharedTypes/MessageTypes";
import { startRegistration } from "@simplewebauthn/browser";

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
    }>(import.meta.env.VITE_PASSKEY_API + "auth/setup", options);

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
    return await fetchData<LoginResponse>(
      import.meta.env.VITE_PASSKEY_API + "auth/verify",
      verifyOptions
    );
  };
  // TODO: Define postLogin function
  const postLogin = async (email) => {
    // TODO: Fetch login setup options
    // TODO: Start authentication process
    // TODO: Fetch and return login verification response
  };

  return { postUser, postLogin };
};

export { useUser, usePasskey };
