const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const morgan = require('morgan');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define models
// User Model
const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['evaluator', 'administrator'],
    default: 'evaluator'
  },
  serviceAreaAssignments: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ServiceArea'
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Check password
UserSchema.methods.comparePassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', UserSchema);

// Technology Model
const TechnologySchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  detailedInformation: {
    type: String
  },
  serviceAreaId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ServiceArea',
    required: true
  },
  status: {
    type: String,
    enum: ['submitted', 'under-review', 'approved', 'rejected', 'published'],
    default: 'submitted'
  },
  submissionDate: {
    type: Date,
    default: Date.now
  },
  publicationDate: {
    type: Date
  },
  tags: [{
    type: String
  }],
  externalLinks: [{
    title: String,
    url: String
  }],
  images: [{
    title: String,
    url: String,
    alt: String
  }],
  submitter: {
    name: String,
    email: String,
    organization: String
  },
  additionalInfo: {
    type: String
  }
});

const Technology = mongoose.model('Technology', TechnologySchema);

// Service Area Model
const ServiceAreaSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  description: {
    type: String
  },
  leadEvaluatorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
});

const ServiceArea = mongoose.model('ServiceArea', ServiceAreaSchema);

// Evaluation Model
const EvaluationSchema = new mongoose.Schema({
  technologyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Technology',
    required: true
  },
  evaluatorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  date: {
    type: Date,
    default: Date.now
  },
  checklistResults: {
    type: Object,
    default: {}
  },
  comments: {
    type: String
  },
  recommendation: {
    type: String,
    enum: ['pass', 'fail', 'revise'],
    required: true
  }
});

const Evaluation = mongoose.model('Evaluation', EvaluationSchema);

// Authentication middleware
const protect = async (req, res, next) => {
  let token;
  
  // Get token from Authorization header
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }
  
  // Check if token exists
  if (!token) {
    return res.status(401).json({ message: 'Not authorized, no token provided' });
  }
  
  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'defaultsecret');
    
    // Set user in request
    req.user = await User.findById(decoded.id).select('-password');
    
    if (!req.user) {
      return res.status(401).json({ message: 'User not found' });
    }
    
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(401).json({ message: 'Not authorized, token failed' });
  }
};

// Role-based authorization
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Not authorized' });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Not authorized for this action' });
    }
    
    next();
  };
};

// Generate JWT token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET || 'defaultsecret', {
    expiresIn: '30d'
  });
};

// API Routes
// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check for user
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await user.comparePassword(password);
    
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Create and return token with user data
    res.json({
      token: generateToken(user._id),
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        serviceAreaAssignments: user.serviceAreaAssignments
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/auth/me', protect, async (req, res) => {
  try {
    res.json({
      _id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      serviceAreaAssignments: req.user.serviceAreaAssignments
    });
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Service Area routes
app.get('/api/service-areas', async (req, res) => {
  try {
    const serviceAreas = await ServiceArea.find().sort({ name: 1 });
    res.json(serviceAreas);
  } catch (error) {
    console.error('Get service areas error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Technologies routes
app.get('/api/technologies', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    // Build query
    let query = {};
    
    // For public access, only show published technologies
    if (!req.headers.authorization) {
      query.status = 'published';
    }
    
    // Add service area filter if provided
    if (req.query.serviceAreaId) {
      query.serviceAreaId = req.query.serviceAreaId;
    }
    
    // Execute query with pagination
    const technologies = await Technology.find(query)
      .sort({ publicationDate: -1, submissionDate: -1 })
      .skip(skip)
      .limit(limit)
      .populate('serviceAreaId', 'name');
    
    // Get total count for pagination
    const total = await Technology.countDocuments(query);
    
    res.json({
      technologies,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Get technologies error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/technologies/:id', async (req, res) => {
  try {
    const technology = await Technology.findById(req.params.id)
      .populate('serviceAreaId', 'name description');
    
    if (!technology) {
      return res.status(404).json({ message: 'Technology not found' });
    }
    
    res.json(technology);
  } catch (error) {
    console.error('Get technology error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// API endpoint to seed initial data
app.post('/api/seed', async (req, res) => {
  try {
    // Clear existing data
    await User.deleteMany({});
    await ServiceArea.deleteMany({});
    await Technology.deleteMany({});
    await Evaluation.deleteMany({});
    
    // Create service areas
    const serviceAreas = [
      { name: 'Bridge Management Systems', description: 'Systems for managing bridge assets and data' },
      { name: 'Condition Assessment/Monitoring', description: 'Technologies for assessing and monitoring bridge conditions' },
      { name: 'Construction', description: 'Innovative construction methods and techniques' },
      { name: 'Design', description: 'Advanced design approaches and tools' },
      { name: 'Equity', description: 'Technologies promoting equitable infrastructure' },
      { name: 'Geotech', description: 'Geotechnical solutions for bridge foundations' },
      { name: 'Innovation', description: 'Emerging and breakthrough technologies' },
      { name: 'Information Science', description: 'Data management and digital technologies' },
      { name: 'Materials', description: 'Advanced and sustainable materials' },
      { name: 'Resiliency', description: 'Technologies enhancing bridge resilience' },
      { name: 'Safety', description: 'Technologies improving bridge safety' }
    ];
    
    const createdServiceAreas = await ServiceArea.insertMany(serviceAreas);
    
    // Map service area names to their IDs
    const serviceAreaMap = {};
    createdServiceAreas.forEach(area => {
      serviceAreaMap[area.name] = area._id;
    });
    
    // Create admin user
    const adminUser = await User.create({
      name: 'Admin User',
      email: 'admin@abtc.org',
      password: 'AdminPass123',
      role: 'administrator'
    });
    
    // Create evaluator users
    const evaluator1 = await User.create({
      name: 'Evaluator 1',
      email: 'evaluator1@abtc.org',
      password: 'EvalPass123',
      role: 'evaluator',
      serviceAreaAssignments: [
        serviceAreaMap['Materials'],
        serviceAreaMap['Construction']
      ]
    });
    
    const evaluator2 = await User.create({
      name: 'Evaluator 2',
      email: 'evaluator2@abtc.org',
      password: 'EvalPass123',
      role: 'evaluator',
      serviceAreaAssignments: [
        serviceAreaMap['Condition Assessment/Monitoring']
      ]
    });
    
    // Create sample technologies
    // Published technologies
    const technology1 = await Technology.create({
      title: 'Fiber Optic Sensor Networks',
      description: 'Advanced monitoring system using fiber optic sensors to monitor structural health in real-time.',
      detailedInformation: '# Fiber Optic Sensor Networks\n\nFiber optic sensor networks represent a significant advancement in bridge monitoring technology.',
      serviceAreaId: serviceAreaMap['Condition Assessment/Monitoring'],
      status: 'published',
      submissionDate: new Date('2024-01-15'),
      publicationDate: new Date('2024-02-10'),
      tags: ['monitoring', 'sensors', 'structural health'],
      externalLinks: [{ title: 'Research Paper', url: 'https://example.com/research' }],
      images: [{
        title: 'Sensor Installation',
        url: 'https://via.placeholder.com/640x360?text=Fiber+Optic+Sensors',
        alt: 'Fiber optic sensors installed on bridge'
      }],
      submitter: {
        name: 'Dr. Sarah Johnson',
        email: 'sjohnson@example.com',
        organization: 'Bridge Monitoring Inc.'
      }
    });
    
    const technology2 = await Technology.create({
      title: 'Ultra-High Performance Concrete',
      description: 'Advanced cementitious material with superior strength, durability, and versatility for bridge applications.',
      detailedInformation: '# Ultra-High Performance Concrete\n\nUHPC is a revolutionary material with exceptional properties.',
      serviceAreaId: serviceAreaMap['Materials'],
      status: 'published',
      submissionDate: new Date('2024-01-20'),
      publicationDate: new Date('2024-02-15'),
      tags: ['materials', 'concrete', 'durability'],
      externalLinks: [{ title: 'Implementation Guide', url: 'https://example.com/uhpc-guide' }],
      images: [{
        title: 'UHPC Application',
        url: 'https://via.placeholder.com/640x360?text=UHPC+Application',
        alt: 'UHPC being applied to bridge components'
      }],
      submitter: {
        name: 'Dr. Michael Lee',
        email: 'mlee@example.com',
        organization: 'Advanced Materials Research'
      }
    });
    
    // Technologies waiting for evaluation
    const technology3 = await Technology.create({
      title: 'Self-Healing Concrete',
      description: 'Innovative concrete with embedded bacteria that automatically repair cracks when they form.',
      detailedInformation: '# Self-Healing Concrete\n\nThis technology embeds bacteria in concrete that activates when cracks form.',
      serviceAreaId: serviceAreaMap['Materials'],
      status: 'submitted',
      submissionDate: new Date('2024-02-25'),
      tags: ['materials', 'concrete', 'self-healing'],
      externalLinks: [{ title: 'Research Paper', url: 'https://example.com/self-healing' }],
      images: [{
        title: 'Self-Healing Process',
        url: 'https://via.placeholder.com/640x360?text=Self-Healing+Process',
        alt: 'Microscopic view of self-healing concrete'
      }],
      submitter: {
        name: 'Prof. Lisa Rodriguez',
        email: 'lrodriguez@example.com',
        organization: 'Sustainable Materials Research'
      }
    });
    
    const technology4 = await Technology.create({
      title: 'Drone Bridge Inspection',
      description: 'Advanced drone systems for comprehensive, efficient, and safe bridge inspections.',
      detailedInformation: '# Drone Bridge Inspection\n\nDrones offer a safer alternative to traditional bridge inspection methods.',
      serviceAreaId: serviceAreaMap['Condition Assessment/Monitoring'],
      status: 'submitted',
      submissionDate: new Date('2024-02-28'),
      tags: ['inspection', 'drones', 'safety'],
      externalLinks: [{ title: 'Case Study', url: 'https://example.com/drone-inspection' }],
      images: [{
        title: 'Inspection Drone',
        url: 'https://via.placeholder.com/640x360?text=Inspection+Drone',
        alt: 'Drone inspecting bridge structure'
      }],
      submitter: {
        name: 'Alex Patel',
        email: 'apatel@example.com',
        organization: 'Advanced Inspection Tech'
      }
    });
    
    res.status(200).json({
      message: 'Database seeded successfully',
      data: {
        serviceAreas: createdServiceAreas.length,
        users: 3,
        technologies: 4
      }
    });
  } catch (error) {
    console.error('Seed error:', error);
    res.status(500).json({ message: 'Error seeding database', error: error.message });
  }
});

// Create a simple HTML file for the root route
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>ABTC API Server</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
      <style>
        body { padding: 40px; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 5px; }
        .endpoint { margin-bottom: 30px; }
        .method { font-weight: bold; display: inline-block; width: 80px; }
        .method-get { color: #0d6efd; }
        .method-post { color: #198754; }
        .method-put { color: #fd7e14; }
        .method-delete { color: #dc3545; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1 class="mb-4">Advanced Bridge Technology Clearinghouse (ABTC) API</h1>
        <p class="lead">This is the API server for the ABTC platform. Use the endpoints below to test the API functionality.</p>
        
        <div class="card mb-4">
          <div class="card-header">
            <h2 class="h5 mb-0">🧪 Test the API</h2>
          </div>
          <div class="card-body">
            <p>You can use the button below to seed the database with sample data:</p>
            <button id="seedBtn" class="btn btn-primary mb-3">Seed Database</button>
            <div id="seedResult" class="alert alert-info d-none"></div>
            
            <hr>
            
            <h3 class="h5 mt-4">View Technologies</h3>
            <button id="getTechnologiesBtn" class="btn btn-secondary">Fetch Technologies</button>
            <div id="technologiesResult" class="mt-3"></div>
            
            <h3 class="h5 mt-4">Login</h3>
            <form id="loginForm" class="mb-3">
              <div class="mb-3">
                <label for="email" class="form-label">Email:</label>
                <input type="email" id="email" class="form-control" value="admin@abtc.org">
              </div>
              <div class="mb-3">
                <label for="password" class="form-label">Password:</label>
                <input type="password" id="password" class="form-control" value="AdminPass123">
              </div>
              <button type="submit" class="btn btn-success">Login</button>
            </form>
            <div id="loginResult" class="alert alert-info d-none"></div>
          </div>
        </div>
        
        <h2>API Endpoints</h2>
        
        <div class="endpoint">
          <h3>Authentication</h3>
          <p><span class="method method-post">POST</span> /api/auth/login</p>
          <p><span class="method method-get">GET</span> /api/auth/me</p>
        </div>
        
        <div class="endpoint">
          <h3>Service Areas</h3>
          <p><span class="method method-get">GET</span> /api/service-areas</p>
        </div>
        
        <div class="endpoint">
          <h3>Technologies</h3>
          <p><span class="method method-get">GET</span> /api/technologies</p>
          <p><span class="method method-get">GET</span> /api/technologies/:id</p>
        </div>
        
        <div class="endpoint">
          <h3>Database Seeding</h3>
          <p><span class="method method-post">POST</span> /api/seed</p>
        </div>
      </div>
      
      <script>
        document.getElementById('seedBtn').addEventListener('click', async () => {
          const resultEl = document.getElementById('seedResult');
          resultEl.textContent = 'Seeding database...';
          resultEl.classList.remove('d-none', 'alert-danger');
          resultEl.classList.add('alert-info');
          
          try {
            const response = await fetch('/api/seed', {
              method: 'POST'
            });
            
            const data = await response.json();
            
            if (response.ok) {
              resultEl.textContent = 'Database seeded successfully!';
              resultEl.classList.remove('alert-info');
              resultEl.classList.add('alert-success');
            } else {
              throw new Error(data.message || 'Failed to seed database');
            }
          } catch (error) {
            resultEl.textContent = error.message;
            resultEl.classList.remove('alert-info');
            resultEl.classList.add('alert-danger');
          }
        });
        
        document.getElementById('getTechnologiesBtn').addEventListener('click', async () => {
          const resultEl = document.getElementById('technologiesResult');
          resultEl.innerHTML = '<div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div>';
          
          try {
            const response = await fetch('/api/technologies');
            const data = await response.json();
            
            if (response.ok) {
              let html = '<div class="table-responsive"><table class="table table-striped">';
              html += '<thead><tr><th>Title</th><th>Service Area</th><th>Status</th><th>Submission Date</th></tr></thead>';
              html += '<tbody>';
              
              data.technologies.forEach(tech => {
                html += '<tr>';
                html += '<td>' + tech.title + '</td>';
                html += '<td>' + (tech.serviceAreaId ? tech.serviceAreaId.name : 'Unknown') + '</td>';
                html += '<td>' + tech.status + '</td>';
                html += '<td>' + new Date(tech.submissionDate).toLocaleDateString() + '</td>';
                html += '</tr>';
              });
              
              html += '</tbody></table></div>';
              resultEl.innerHTML = html;
            } else {
              throw new Error(data.message || 'Failed to fetch technologies');
            }
          } catch (error) {
            resultEl.innerHTML = '<div class="alert alert-danger">' + error.message + '</div>';
          }
        });
        
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          
          const email = document.getElementById('email').value;
          const password = document.getElementById('password').value;
          const resultEl = document.getElementById('loginResult');
          
          resultEl.textContent = 'Logging in...';
          resultEl.classList.remove('d-none', 'alert-danger', 'alert-success');
          resultEl.classList.add('alert-info');
          
          try {
            const response = await fetch('/api/auth/login', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ email, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
              resultEl.textContent = 'Login successful! User: ' + data.user.name + ' (Role: ' + data.user.role + ')';
              resultEl.classList.remove('alert-info');
              resultEl.classList.add('alert-success');
              localStorage.setItem('token', data.token);
            } else {
              throw new Error(data.message || 'Login failed');
            }
          } catch (error) {
            resultEl.textContent = error.message;
            resultEl.classList.remove('alert-info');
            resultEl.classList.add('alert-danger');
          }
        });
      </script>
    </body>
    </html>
  `);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Server error', error: process.env.NODE_ENV === 'development' ? err.message : undefined });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
