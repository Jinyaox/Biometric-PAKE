### DOCUMENTATION: This is the basic supporting packet that contains all the actual implementation of the final Bio-PAKE ###
import numpy as np
import os
from tqdm import tqdm
import face_recognition
import json

"""
1. The Cosine LSH functionality
"""

class CosineLSH:

    def __init__(self, hashed_bits, dimension, seed=None):
        #---------------- Avoid High Dimensionality, use JL Lemma to reduce dimension----------------
        rng = np.random.default_rng(seed)

        #-------------------------- this part defines all the standard LSH mechanism -------------------
        self.num_bits = hashed_bits
        self.dimension = dimension
        
        # Generate random hyperplanes
        self.hyperplanes = rng.standard_normal(size=(hashed_bits, dimension))

        norms = np.linalg.norm(self.hyperplanes, axis=1, keepdims=True)
        
        # Avoid division by zero (unlikely with Gaussian, but good practice)
        norms[norms == 0] = 1 
        
        self.hyperplanes = self.hyperplanes / norms

        self.filtered_indices = None
    
    @staticmethod
    def to_fixed_width(n, bit_width):
        # Create a mask of all 1s for the desired width
        mask = (1 << bit_width) - 1
        # Force the number into that width
        return n & mask
    
    @staticmethod
    def quantize_array(arr, k: int=12):
        """
        Quantizes a real-number array (1D vector or 2D matrix) into a k-bit signed integer array.
        Uses max-scaling to prevent zero-collapse at extremely low bit depths.
        """
        M = (1 << (k - 1)) - 1
        
        # Scale the array so its largest absolute value is exactly 1.0.
        # This prevents 2-bit or 3-bit quantization from collapsing everything to 0.
        max_val = np.max(np.abs(arr))
        if max_val > 0:
            arr_scaled = arr / max_val
        else:
            arr_scaled = arr
            
        # FIXED: Enforce 64-bit integers to prevent dot-product overflow at 16-bit!
        v_quantized = np.round(arr_scaled * M).astype(np.int64)
        v_quantized = np.clip(v_quantized, -M, M)
        
        return v_quantized

    def hash(self, vector, k_bits=12):
        if k_bits is not None:
            # Use quantize_array for BOTH the 1D face vector and the 2D hyperplanes
            vector = self.quantize_array(vector, k_bits)
            active_hyperplanes = self.quantize_array(self.hyperplanes, k_bits)
        else:
            active_hyperplanes = self.hyperplanes
            
        # Project the vector onto each hyperplane (Pure Integer Math if k_bits is set!)
        projections = np.dot(active_hyperplanes, vector)
        
        signs = projections >= 0
        
        hash_code = 0
        for bit in signs:
            hash_code = (hash_code << 1) | int(bit)
            
        return self.to_fixed_width(int(hash_code), self.num_bits)
    
    def filter_by_hyperplane(self, vector, num_vec, k_bits=None): 
        if k_bits is not None:
            # Use quantize_array for BOTH the 1D face vector and the 2D hyperplanes
            vector = self.quantize_array(vector, k_bits)
            active_hyperplanes = self.quantize_array(self.hyperplanes, k_bits)
        else:
            active_hyperplanes = self.hyperplanes
            
        norm_vec = np.linalg.norm(vector)
        if norm_vec == 0:
            self.filtered_indices = np.array([], dtype=int)
            return self.filtered_indices
        
        unit_vec = vector / norm_vec

        # Cosine requires the hyperplanes to also be normalized if they were quantized
        norm_hp = np.linalg.norm(active_hyperplanes, axis=1, keepdims=True)
        norm_hp[norm_hp == 0] = 1
        unit_hp = active_hyperplanes / norm_hp

        # Calculate Cosine
        cos_theta = np.dot(unit_hp, unit_vec)
        
        abs_cos = np.abs(cos_theta)
        sorted_indices = np.argsort(abs_cos)
        bad_indices = sorted_indices[:num_vec]

        self.filtered_indices = bad_indices
        return bad_indices

    def filtered_hamming_weights(self, intA: int, intB: int, hmwT: int = 0) -> int:
        if self.filtered_indices is None: 
            raise AssertionError("No existing Filtering")

        # 1. Calculate Standard XOR
        xor_result = intA ^ intB

        ignore_mask = 0
        shifts = (self.num_bits - 1) - self.filtered_indices
        for shift in shifts:
            ignore_mask |= (1 << int(shift))

        full_mask = (1 << self.num_bits) - 1
        clean_inverse_mask = (~ignore_mask) & full_mask
        
        filtered_xor = xor_result & clean_inverse_mask
        actual_flips = bin(filtered_xor).count('1')
        
        # Subtract the allowed tolerance. Floor at 0 so any check for 'distance == 0' still works.
        return max(0, actual_flips - hmwT)

    def hamming_distance(self, a: int, b: int) -> int:
        return bin(a ^ b).count('1')
    
# ------------------------------------------this following performs the feature extractions for faces-----------------------

def subfolder_names(parent_folder):
    # Iterate over all entries in parent folder
    for entry in os.listdir(parent_folder):
        full_path = os.path.join(parent_folder, entry)
        if os.path.isdir(full_path):
            yield full_path


# Now I want to define a generator to generate all files within a particular folder
def images_in_folder(folder_path):
    for filename in os.listdir(folder_path):
        full_path = os.path.join(folder_path, filename)
        if os.path.isfile(full_path) and filename.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp')):
            yield full_path

def images_to_encoding(path):
    image = face_recognition.load_image_file(path)
    
    if(len(face_recognition.face_encodings(image))==0): 
        return [None]

    if(len(face_recognition.face_encodings(image)[0])!=0):
        return face_recognition.face_encodings(image)[0]

    return [None]
    

def encode_all_files(filename:str,folder_extracted:str,cap=300):
    all_folders=[image for image in subfolder_names("faces")]
    facial_data=dict()

    for folder in tqdm(all_folders): # for a specific person
        facial_data[folder]=[]

        counter=0

        for image in images_in_folder(folder):
            encoding=images_to_encoding(image)

            if encoding[0]==None:
                continue

            facial_data[folder].append(encoding)

            if counter==cap: break
            else: counter+=1
    with open(f"data_{folder_extracted}.json", "a") as f:
        json.dump(facial_data, f, indent=4, default=lambda o:
                o.tolist() if isinstance(o, np.ndarray) else str(o))
