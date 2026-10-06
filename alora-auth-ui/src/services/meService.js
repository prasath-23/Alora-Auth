import { api } from './apiClient'

export const listApps = () => api.get('/api/me/apps')

export const changePassword = (currentPassword, newPassword) =>
  api.post('/api/me/change-password', { current_password: currentPassword, new_password: newPassword })
