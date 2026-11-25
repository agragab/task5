import Joi from 'joi';
import bcrypt from 'bcryptjs';
import { Instructor } from '../models/Instructor.js';

const loginSchema = Joi.object({
  username: Joi.string().trim().max(100).required(),
  password: Joi.string().max(200).required()
});

const searchSchema = Joi.object({
  name: Joi.string().trim().max(100),
  department: Joi.string().trim().max(100)
});

const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

export async function loginInstructor(req, res, next) {
  try {
    const { value, error } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: 'Invalid input' });

    const instructor = await Instructor.findOne({ username: value.username }).select('+password');
    const ok = instructor && (await bcrypt.compare(value.password, instructor.password));
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    res.json({ instructor: publicProfile(instructor) });
  } catch (err) { next(err); }
}

export async function searchInstructors(req, res, next) {
  try {
    const { value, error } = searchSchema.validate(req.query);
    if (error) return res.status(400).json({ message: 'Invalid query' });

    const filter = {};
    if (value.name) filter.name = { $regex: escapeRegex(value.name), $options: 'i' };
    if (value.department) filter.department = value.department;

    const instructors = await Instructor.find(filter).select('name department role').lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) { next(err); }
}

export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

