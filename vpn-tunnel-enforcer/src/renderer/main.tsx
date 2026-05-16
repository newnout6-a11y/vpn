import React from 'react'
import ReactDOM from 'react-dom/client'
import './i18n' // Initialize i18n before rendering
import App from './App'
import './styles/globals.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
