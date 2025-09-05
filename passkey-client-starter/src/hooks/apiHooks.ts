import fetchData from '@/lib/fetchData';
import { LoginResponse, UserResponse } from '@sharedTypes/MessageTypes';
// TODO: add imports for WebAuthn functions

const useUser = () => {
  // TODO: implement network functions for auth server user endpoints
  const getUserByToken = async (token: string) => {
    const options = {
      headers: {
        Authorization: 'Bearer ' + token,
      },
    };
    return await fetchData<UserResponse>(
      import.meta.env.VITE_AUTH_API + '/users/token/',
      options,
    );
  };

  const getUsernameAvailable = async (username: string) => {
    return await fetchData<{ available: boolean }>(
      import.meta.env.VITE_AUTH_API + '/users/username/' + username,
    );
  };

  const getEmailAvailable = async (email: string) => {
    return await fetchData<{ available: boolean }>(
      import.meta.env.VITE_AUTH_API + '/users/email/' + email,
    );
  };

  return { getUserByToken, getUsernameAvailable, getEmailAvailable };
};

// TODO: Define usePasskey hook
const usePasskey = () => {
  // TODO: Define postUser function
  const postUser = async (user) => {
    // TODO: Set up request options
    // TODO: Fetch setup response
    // TODO: Start registration process
    // TODO: Prepare data for verification
    // TODO: Fetch and return verification response
  };

  // TODO: Define postLogin function
  const postLogin = async (email) => {
    // TODO: Fetch login setup options
    // TODO: Start authentication process
    // TODO: Fetch and return login verification response
  };

  // TODO: Return postUser and postLogin functions
  return { postUser, postLogin };
};

export { useUser, usePasskey };
