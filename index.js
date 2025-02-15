const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();


const { initialiseDatabase } = require("./db/db.connect.js");
const User = require("./models/user.model.js");
const Album = require("./models/album.model.js");
const Image = require("./models/image.model.js")

const app = express();
const PORT = process.env.PORT || 4000;

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer config
const storage = multer.diskStorage({});
const upload = multer({
    storage,
    fileFilter: function (req, file, cb) {
        if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
            return cb(new Error('Only image files are allowed!'), false);
        }
        cb(null, true);
    }
});



// Middleware
app.use(express.json());
app.use(cors({ credentials: true, origin: process.env.FRONTEND_URL }));
app.use(cookieParser());

// Initialize Database
initialiseDatabase();

// Authentication Middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies.access_token;

  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token." });
  }
};

// Authentication Routes
app.post("/auth/register", async (req, res) => {
  const { username, name, password } = req.body;

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const user = new User({
      username,
      name,
      password: hashedPassword,
    });

    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error registering user", error: error.message });
  }
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid password" });
    }

    // Create token
    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Set token in cookie
    res.cookie("access_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    res.json({ message: "Logged in successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error logging in", error: error.message });
  }
});

app.post("/auth/logout", (req, res) => {
  res.clearCookie("access_token");
  res.json({ message: "Logged out successfully" });
});

// Add these routes to your index.js

// Create Album
app.post("/albums", verifyToken, async (req, res) => {
  const { name, description } = req.body;
  const userId = req.user.id;

  try {
    const newAlbum = new Album({
      name,
      description,
      owner: userId,
    });

    const savedAlbum = await newAlbum.save();
    res
      .status(201)
      .json({ message: "Album created successfully", album: savedAlbum });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error creating album", error: error.message });
  }
});

// Get All Albums for User
app.get("/albums", verifyToken, async (req, res) => {
  try {
    const albums = await Album.find({ owner: req.user.id });
    res.json({ albums });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error fetching albums", error: error.message });
  }
});

// Get Single Album
app.get("/albums/:id", verifyToken, async (req, res) => {
  try {
    const album = await Album.findById(req.params.id);
    if (!album) {
      return res.status(404).json({ message: "Album not found" });
    }

    // Check if user owns album or is shared with them
    if (
      album.owner !== req.user.id &&
      !album.sharedUsers.includes(req.user.username)
    ) {
      return res.status(403).json({ message: "Access denied" });
    }

    res.json({ album });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error fetching album", error: error.message });
  }
});

// Update Album
app.put("/albums/:id", verifyToken, async (req, res) => {
  try {
    const album = await Album.findById(req.params.id);
    if (!album) {
      return res.status(404).json({ message: "Album not found" });
    }

    if (album.owner !== req.user.id) {
      return res
        .status(403)
        .json({ message: "Not authorized to update this album" });
    }

    const updatedAlbum = await Album.findByIdAndUpdate(
      req.params.id,
      { $set: req.body },
      { new: true }
    );

    res.json({ message: "Album updated successfully", album: updatedAlbum });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error updating album", error: error.message });
  }
});

// Delete Album
app.delete("/albums/:id", verifyToken, async (req, res) => {
  try {
    const album = await Album.findById(req.params.id);
    if (!album) {
      return res.status(404).json({ message: "Album not found" });
    }

    if (album.owner !== req.user.id) {
      return res
        .status(403)
        .json({ message: "Not authorized to delete this album" });
    }

    await Album.findByIdAndDelete(req.params.id);
    // Also delete all images in this album
    await Image.deleteMany({ albumId: req.params.id });

    res.json({ message: "Album and associated images deleted successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error deleting album", error: error.message });
  }
});

// Share Album
app.post("/albums/:id/share", verifyToken, async (req, res) => {
  const { usernames } = req.body;

  try {
    const album = await Album.findById(req.params.id);
    if (!album) {
      return res.status(404).json({ message: "Album not found" });
    }

    if (album.owner !== req.user.id) {
      return res
        .status(403)
        .json({ message: "Not authorized to share this album" });
    }

    // Add new users to shared list (avoid duplicates)
    album.sharedUsers = [...new Set([...album.sharedUsers, ...usernames])];
    await album.save();

    res.json({ message: "Album shared successfully", album });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error sharing album", error: error.message });
  }
});

// Upload image to album
app.post("/albums/:albumId/images", verifyToken, upload.single("file"), async (req, res) => {
    try {
        const { albumId } = req.params;
        const { tags, person, isFavorite, name } = req.body;
        const userId = req.user.id;

        const album = await Album.findById(albumId);
        if (!album) {
            return res.status(404).json({ message: "Album not found" });
        }

        if (userId !== album.owner) {
            return res.status(403).json({ message: "Not authorized to upload to this album" });
        }

        const file = req.file;
        if (!file) {
            return res.status(400).json({ message: "No file uploaded" });
        }

        const fileSize = fs.statSync(file.path).size;
        if (fileSize > 5 * 1024 * 1024) {
            return res.status(400).json({ message: "File size exceeds 5MB limit" });
        }

        const result = await cloudinary.uploader.upload(file.path, {
            folder: "uploads"
        });

        const newImage = new Image({
            albumId,
            file: result.secure_url,
            tags: tags ? tags.split(",").map(tag => tag.trim()) : [],
            person,
            isFavorite: isFavorite || false,
            name,
            size: fileSize
        });

        await newImage.save();
        res.status(201).json({ message: "Image uploaded successfully", image: newImage });
    } catch (error) {
        res.status(500).json({ error: "Internal server error" });
    }
});

// Get images in album
app.get("/albums/:albumId/images", verifyToken, async (req, res) => {
    try {
        const { albumId } = req.params;
        const { tags } = req.query;

        const query = { albumId };
        if (tags) {
            query.tags = { $in: tags.split(",").map(tag => tag.trim()) };
        }

        const images = await Image.find(query).populate("comments.user");
        res.json({ images });
    } catch (error) {
        res.status(500).json({ error: "Internal server error" });
    }
});

// Toggle favorite status
app.put("/albums/:albumId/images/:imageId/favorite", verifyToken, async (req, res) => {
    try {
        const { albumId, imageId } = req.params;
        const userId = req.user.id;

        const album = await Album.findById(albumId);
        if (!album) {
            return res.status(404).json({ message: "Album not found" });
        }

        if (userId !== album.owner) {
            return res.status(403).json({ message: "Not authorized" });
        }

        const image = await Image.findByIdAndUpdate(
            imageId,
            [{ $set: { isFavorite: { $not: "$isFavorite" } } }],
            { new: true }
        );

        if (!image) {
            return res.status(404).json({ message: "Image not found" });
        }

        res.json({ message: "Favorite status updated", image });
    } catch (error) {
        res.status(500).json({ error: "Internal server error" });
    }
});

// Delete image
app.delete("/albums/:albumId/images/:imageId", verifyToken, async (req, res) => {
    try {
        const { albumId, imageId } = req.params;
        const userId = req.user.id;

        const album = await Album.findById(albumId);
        if (!album) {
            return res.status(404).json({ message: "Album not found" });
        }

        if (userId !== album.owner) {
            return res.status(403).json({ message: "Not authorized" });
        }

        const image = await Image.findByIdAndDelete(imageId);
        if (!image) {
            return res.status(404).json({ message: "Image not found" });
        }

        // Could also delete from Cloudinary here if needed
        // await cloudinary.uploader.destroy(image.cloudinaryId);

        res.json({ message: "Image deleted successfully" });
    } catch (error) {
        res.status(500).json({ error: "Internal server error" });
    }
});

// Add these routes to your existing code

// Get user profile
app.get("/profile", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');  // exclude password
        res.json({ user });
    } catch (error) {
        res.status(500).json({ message: "Error fetching profile" });
    }
});

// Update profile
app.put("/profile", verifyToken, async (req, res) => {
    try {
        const { name, profilePicture } = req.body;
        
        const updatedUser = await User.findByIdAndUpdate(
            req.user.id,
            { 
                name,
                profilePicture
            },
            { new: true }
        ).select('-password');

        res.json({ message: "Profile updated", user: updatedUser });
    } catch (error) {
        res.status(500).json({ message: "Error updating profile" });
    }
});

// Change password
app.put("/profile/password", verifyToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        const user = await User.findById(req.user.id);
        const validPassword = await bcrypt.compare(currentPassword, user.password);
        
        if (!validPassword) {
            return res.status(400).json({ message: "Current password is incorrect" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();

        res.json({ message: "Password updated successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error updating password" });
    }
});

// Add this route to your existing code

app.get("/search/images", verifyToken, async (req, res) => {
    try {
        const { query, tags, person, albumId, favorite } = req.query;
        
        // Build search criteria
        const searchCriteria = {};
        
        // If albumId is provided, search in specific album
        if (albumId) {
            const album = await Album.findById(albumId);
            if (!album) {
                return res.status(404).json({ message: "Album not found" });
            }
            
            // Check if user has access to this album
            if (album.owner !== req.user.id && !album.sharedUsers.includes(req.user.username)) {
                return res.status(403).json({ message: "Access denied" });
            }
            searchCriteria.albumId = albumId;
        } else {
            // If no albumId, search in user's albums
            const userAlbums = await Album.find({ 
                $or: [
                    { owner: req.user.id },
                    { sharedUsers: req.user.username }
                ]
            });
            searchCriteria.albumId = { $in: userAlbums.map(album => album._id) };
        }

        // Add other search criteria
        if (query) {
            searchCriteria.name = { $regex: query, $options: 'i' };  // Case-insensitive search
        }
        
        if (tags) {
            searchCriteria.tags = { 
                $in: tags.split(',').map(tag => new RegExp(tag.trim(), 'i')) 
            };
        }
        
        if (person) {
            searchCriteria.person = { $regex: person, $options: 'i' };
        }
        
        if (favorite === 'true') {
            searchCriteria.isFavorite = true;
        }

        const images = await Image.find(searchCriteria)
            .populate('comments.user', 'username name')
            .sort({ createdAt: -1 });  // Most recent first

        res.json({ images });
    } catch (error) {
        res.status(500).json({ message: "Error searching images" });
    }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
