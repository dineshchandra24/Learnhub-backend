const mongoose = require('mongoose');
require('dotenv').config();

const courseSchema = new mongoose.Schema({
  title: String,
  instructor: String,
  category: String,
  rating: Number,
  reviews: Number,
  students: Number,
  duration: String,
  price: Number,
  image: String,
  description: String,
  lessons: Number,
  level: String,
  bestseller: Boolean
});

const Course = mongoose.model('Course', courseSchema);

const sampleCourses = [
  {
    title: 'Complete Web Development Bootcamp',
    instructor: 'Priya Sharma',
    category: 'development',
    rating: 4.8,
    reviews: 2430,
    students: 8500,
    duration: '52 hours',
    price: 499,
    image: 'https://images.unsplash.com/photo-1498050108023-c5249f4df085?w=400&h=250&fit=crop',
    description: 'Master web development from scratch with HTML, CSS, JavaScript, React, Node.js, and more.',
    lessons: 245,
    level: 'Beginner',
    bestseller: true
  },
  // Add more courses...
];

mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log('Connected to MongoDB');
    await Course.deleteMany({});
    await Course.insertMany(sampleCourses);
    console.log('✅ Courses seeded successfully');
    process.exit(0);
  })
  .catch(err => {
    console.error('Error:', err);
    process.exit(1);
  });