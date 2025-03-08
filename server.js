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

// Create index for text search
TechnologySchema.index({
  title: 'text',
  description: 'text',
  detailedInformation: 'text',
  tags: 'text',
  'submitter.organization': 'text'
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
    const query = { status: 'published' };
    
    // Add service area filter if provided
    if (req.query.serviceAreaId) {
      query.serviceAreaId = req.query.serviceAreaId;
    }
    
    // Add featured filter if requested
    if (req.query.featured === 'true') {
      // For featured, just use most recent
      limit_val = parseInt(req.query.limit) || 4;
    }
    
    // Add text search if provided
    if (req.query.search) {
      query.$text = { $search: req.query.search };
    }
    
    // Execute query with pagination
    const technologies = await Technology.find(query)
      .sort({ publicationDate: -1 })
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

// Suggestions route
app.post('/api/suggestions', async (req, res) => {
  try {
    const {
      title,
      description,
      serviceAreaId,
      externalLink,
      submitterName,
      submitterEmail,
      submitterOrganization,
      additionalInfo
    } = req.body;
    
    // Create new technology
    const technology = new Technology({
      title,
      description,
      serviceAreaId,
      status: 'submitted',
      externalLinks: externalLink ? [{ title: 'External Link', url: externalLink }] : [],
      submitter: {
        name: submitterName,
        email: submitterEmail,
        organization: submitterOrganization
      },
      additionalInfo
    });
    
    await technology.save();
    
    res.status(201).json({ message: 'Technology suggestion submitted successfully' });
  } catch (error) {
    console.error('Submit suggestion error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Evaluations routes
app.get('/api/evaluations/pending', protect, authorize('evaluator', 'administrator'), async (req, res) => {
  try {
    // Get technologies that:
    // 1. Are in 'submitted' or 'under-review' status
    // 2. Match the evaluator's service areas
    // 3. Have not been evaluated by this evaluator
    
    // Find technologies in relevant service areas
    const serviceAreaIds = req.user.serviceAreaAssignments;
    
    // Find technologies with the right status and service area
    const technologies = await Technology.find({
      status: { $in: ['submitted', 'under-review'] },
      serviceAreaId: { $in: serviceAreaIds }
    }).populate('serviceAreaId', 'name');
    
    // Filter out technologies already evaluated by this user
    const evaluatedTechIds = await Evaluation.find({ 
      evaluatorId: req.user._id 
    }).distinct('technologyId');
    
    // Filter out already evaluated technologies
    const pendingTechnologies = technologies.filter(
      tech => !evaluatedTechIds.includes(tech._id.toString())
    );
    
    res.json(pendingTechnologies);
  } catch (error) {
    console.error('Get pending evaluations error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/evaluations/completed', protect, authorize('evaluator', 'administrator'), async (req, res) => {
  try {
    const evaluations = await Evaluation.find({ 
      evaluatorId: req.user._id 
    }).populate({
      path: 'technologyId',
      select: 'title status serviceAreaId submissionDate publicationDate',
      populate: {
        path: 'serviceAreaId',
        select: 'name'
      }
    }).sort({ date: -1 });
    
    res.json(evaluations);
  } catch (error) {
    console.error('Get completed evaluations error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/evaluations/technology/:id', protect, authorize('evaluator', 'administrator'), async (req, res) => {
  try {
    const evaluation = await Evaluation.findOne({
      technologyId: req.params.id,
      evaluatorId: req.user._id
    });
    
    if (!evaluation) {
      return res.status(404).json({ message: 'Evaluation not found' });
    }
    
    res.json(evaluation);
  } catch (error) {
    console.error('Get evaluation error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/evaluations/:id', protect, authorize('evaluator', 'administrator'), async (req, res) => {
  try {
    const { checklistResults, comments, recommendation } = req.body;
    
    // Check if technology exists
    const technology = await Technology.findById(req.params.id);
    
    if (!technology) {
      return res.status(404).json({ message: 'Technology not found' });
    }
    
    // Check if user is assigned to this service area
    if (!req.user.serviceAreaAssignments.includes(technology.serviceAreaId.toString())) {
      return res.status(403).json({ message: 'Not authorized to evaluate this technology' });
    }
    
    // Check if already evaluated
    const existingEvaluation = await Evaluation.findOne({
      technologyId: req.params.id,
      evaluatorId: req.user._id
    });
    
    if (existingEvaluation) {
      return res.status(400).json({ message: 'You have already evaluated this technology' });
    }
    
    // Create new evaluation
    const evaluation = new Evaluation({
      technologyId: req.params.id,
      evaluatorId: req.user._id,
      checklistResults,
      comments,
      recommendation
    });
    
    await evaluation.save();
    
    // Update technology status to under-review if it was submitted
    if (technology.status === 'submitted') {
      technology.status = 'under-review';
      await technology.save();
    }
    
    res.status(201).json({ message: 'Evaluation submitted successfully' });
  } catch (error) {
    console.error('Submit evaluation error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin routes
app.get('/api/admin/technologies', protect, authorize('administrator'), async (req, res) => {
  try {
    const technologies = await Technology.find()
      .sort({ submissionDate: -1 })
      .populate('serviceAreaId', 'name');
    
    res.json(technologies);
  } catch (error) {
    console.error('Admin get technologies error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/admin/technologies', protect, authorize('administrator'), async (req, res) => {
  try {
    const technology = new Technology(req.body);
    await technology.save();
    
    res.status(201).json(technology);
  } catch (error) {
    console.error('Admin create technology error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/admin/technologies/:id', protect, authorize('administrator'), async (req, res) => {
  try {
    const technology = await Technology.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    
    if (!technology) {
      return res.status(404).json({ message: 'Technology not found' });
    }
    
    res.json(technology);
  } catch (error) {
    console.error('Admin update technology error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/admin/technologies/:id/publish', protect, authorize('administrator'), async (req, res) => {
  try {
    const technology = await Technology.findById(req.params.id);
    
    if (!technology) {
      return res.status(404).json({ message: 'Technology not found' });
    }
    
    technology.status = 'published';
    technology.publicationDate = new Date();
    await technology.save();
    
    res.json(technology);
  } catch (error) {
    console.error('Admin publish technology error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/users', protect, authorize('administrator'), async (req, res) => {
  try {
    const users = await User.find()
      .select('-password')
      .sort({ name: 1 });
    
    res.json(users);
  } catch (error) {
    console.error('Admin get users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/users/:id', protect, authorize('administrator'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Admin get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/admin/users', protect, authorize('administrator'), async (req, res) => {
  try {
    const { email } = req.body;
    
    // Check if user exists
    const userExists = await User.findOne({ email });
    
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }
    
    const user = new User(req.body);
    await user.save();
    
    // Remove password from response
    const userResponse = user.toObject();
    delete userResponse.password;
    
    res.status(201).json(userResponse);
  } catch (error) {
    console.error('Admin create user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/admin/users/:id', protect, authorize('administrator'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Update fields
    const { name, email, role, serviceAreaAssignments, password } = req.body;
    
    if (name) user.name = name;
    if (email) user.email = email;
    if (role) user.role = role;
    if (serviceAreaAssignments) user.serviceAreaAssignments = serviceAreaAssignments;
    
    // Only update password if provided
    if (password) {
      user.password = password;
    }
    
    await user.save();
    
    // Remove password from response
    const userResponse = user.toObject();
    delete userResponse.password;
    
    res.json(userResponse);
  } catch (error) {
    console.error('Admin update user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/admin/users/:id', protect, authorize('administrator'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Don't allow deleting the last admin
    if (user.role === 'administrator') {
      const adminCount = await User.countDocuments({ role: 'administrator' });
      
      if (adminCount <= 1) {
        return res.status(400).json({ message: 'Cannot delete the last administrator' });
      }
    }
    
    await user.deleteOne();
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Admin delete user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// API endpoint to seed initial data - only for development and testing
app.post('/api/seed', async (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ message: 'Seed endpoint is not available in production' });
  }
  
  try {
    // Define service areas
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
    
    // Create admin user
    const adminExists = await User.findOne({ email: 'admin@abtc.org' });
    if (!adminExists) {
      await User.create({
        name: 'Admin User',
        email: 'admin@abtc.org',
        password: 'AdminPass123',
        role: 'administrator'
      });
    }
    
    // Create service areas
    await ServiceArea.deleteMany({});
    const createdServiceAreas = await ServiceArea.insertMany(serviceAreas);
    
    // Create sample technology
    const serviceAreaMap = {};
    createdServiceAreas.forEach(area => {
      serviceAreaMap[area.name] = area._id;
    });
    
    await Technology.deleteMany({});
    await Technology.create({
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
    
    // Create evaluator
    const evaluatorExists = await User.findOne({ email: 'evaluator@abtc.org' });
    if (!evaluatorExists) {
      await User.create({
        name: 'Evaluator User',
        email: 'evaluator@abtc.org',
        password: 'EvalPass123',
        role: 'evaluator',
        serviceAreaAssignments: [
          serviceAreaMap['Condition Assessment/Monitoring'],
          serviceAreaMap['Materials']
        ]
      });
    }
    
    res.json({ message: 'Database seeded successfully' });
  } catch (error) {
    console.error('Seed error:', error);
    res.status(500).json({ message: 'Seeding failed', error: error.message });
  }
});

// Serve static assets in production
if (process.env.NODE_ENV === 'production') {
  const buildPath = path.join(__dirname, 'build');
  
  app.use(express.static(buildPath));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(buildPath, 'index.html'));
  });
} else {
  // For development/testing
  app.get('/', (req, res) => {
    res.send('API is running');
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Server error', error: process.env.NODE_ENV === 'development' ? err.message : undefined });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
