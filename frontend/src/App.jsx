import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ToastProvider } from './components/visuals/Toast';
import Landing from './components/Landing';
import Login from './components/Login';
import Register from './components/Register';
import ChatDashboard from './components/ChatDashboard';
import './App.css';

function PrivateRoute({ children }) {
  const isAuthenticated = !!localStorage.getItem('qchat_token');
  return isAuthenticated ? children : <Navigate to="/login" replace />;
}

function App() {
  return (
    <ToastProvider>
      <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route
          path="/chat"
          element={<PrivateRoute><ChatDashboard /></PrivateRoute>}
        />
        <Route path="/" element={<Landing />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      </Router>
    </ToastProvider>
  );
}

export default App;
