const { z } = require('zod');
const { handleValidationError } = require('./ValidateQuestions');

const savedAchievementsSchema = z.object({
  unlockedAchievements: z
    .array(
      z
        .string()
        .trim()
        .min(1, 'Achievement ID cannot be empty')
        .max(60, 'Achievement ID cannot exceed 60 characters'),
      {
        required_error: 'unlockedAchievements must be an array',
        invalid_type_error: 'unlockedAchievements must be an array of strings',
      }
    )
    .refine(
      (achievements) => new Set(achievements).size === achievements.length,
      { message: 'Duplicate achievement IDs are not allowed' }
    ),
});

const validateSavedAchievements = (req, res, next) => {
  try {
    // Validate and store the parsed data
    req.body = savedAchievementsSchema.parse(req.body);
    next();
  } catch (error) {
    return handleValidationError(res, error);
  }
};

module.exports = {
  validateSavedAchievements,
};
