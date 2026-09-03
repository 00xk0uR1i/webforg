import axios from 'axios'
import { getErrorMessage } from '../utils/error'

const api = axios.create({ baseURL: '/api' })

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      window.dispatchEvent(new Event('auth:expired'))
    }
    err.userMessage = getErrorMessage(err)
    return Promise.reject(err)
  }
)

export default api
