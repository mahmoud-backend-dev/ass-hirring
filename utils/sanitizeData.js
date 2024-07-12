export function sanitizeData(user) {
  return {
    id: user._id,
    fullName:user.fullName,
    Email: user.Email,
  }
} 
