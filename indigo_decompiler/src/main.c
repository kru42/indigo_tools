#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum Opcode
{
    // Arithmetic and Assignment Operations
    AssignAdd, // Assign result of addition to a variable
    AssignSub, // Assign result of subtraction to a variable
    Assign,    // Simple assignment
    Add,       // Addition operation
    Sub,       // Subtraction operation
    Mul,       // Multiplication operation

    // Comparison Operations
    NE, // Not Equal
    EQ, // Equal
    GE, // Greater than or Equal
    GT, // Greater than
    LE, // Less than or Equal
    LT, // Less than

    // Object and Array Operations
    Delete,        // Delete an object
    New,           // Create a new object
    CopyCtor,      // Copy constructor
    SetFromPoint,  // Set object from a point
    SetFromPoints, // Set object from multiple points
    ArrayPop,      // Pop from an array
    ArrayAdd,      // Add to an array
    ArrayCheck,    // Check an array
    ArrayMul,      // Multiply array elements
    ArrayPopSrcP,  // Pop source pointer from an array
    ArrayPushSrcP, // Push source pointer to an array
    ArrayPopDstP,  // Pop destination pointer from an array
    ArrayPushDstP, // Push destination pointer to an array
    ArrayPopRetP,  // Pop return pointer from an array
    ArrayPushRetP, // Push return pointer to an array
    ArrayInitC,    // Initialize array with constant

    // Memory Management
    Allocate,          // Allocate memory
    Deallocate,        // Deallocate memory
    CopyBytesToSP,     // Copy bytes to stack pointer
    CopyBytesToSP_4,   // Copy 4 bytes to stack pointer
    CopyBytesFromSP,   // Copy bytes from stack pointer
    Memcpy,            // Memory copy
    Memcpy_4,          // Memory copy 4 bytes
    CopyAddress,       // Copy memory address
    PushStaticPointer, // Push static pointer

    // Stack and Pointer Operations
    PushString,     // Push a string onto the stack
    PushStringToRP, // Push a string to a return pointer
    PushAdrString,  // Push address of a string
    PushNULL,       // Push null value
    PushAdrNULL,    // Push address of null value
    PushThis,       // Push 'this' reference
    PushAdrThis,    // Push address of 'this'
    PushParent,     // Push parent reference
    PushAdrParent,  // Push address of parent
    PushRP,         // Push return pointer
    PushWP,         // Push working pointer
    PopWP,          // Pop working pointer

    // Offset and Address Operations
    PushOffsetThis,       // Push offset of 'this'
    PushLongOffsetThis,   // Push long offset of 'this'
    PushOffsetParent,     // Push offset of parent
    PushLongOffsetParent, // Push long offset of parent
    PushOffsetLP,         // Push offset of local pointer
    PushOffsetLP_0,       // Push offset of local pointer with specific offset
    PushOffsetLP_1,       // Push offset of local pointer with specific offset
    PushOffsetLP_4,       // Push offset of local pointer with specific offset
    PushOffsetLP_8,       // Push offset of local pointer with specific offset
    PushOffsetLP_12,      // Push offset of local pointer with specific offset
    PushOffsetLP_16,      // Push offset of local pointer with specific offset
    PushLongOffsetLP,     // Push long offset of local pointer
    PushOffsetPP,         // Push offset of parent pointer
    PushOffsetPP_0,       // Push offset of parent pointer with specific offset
    PushOffsetPP_4,       // Push offset of parent pointer with specific offset
    PushLongOffsetPP,     // Push long offset of parent pointer

    // Data Type Conversions
    ToBool,        // Convert to boolean
    ToChar,        // Convert to character
    ToInt,         // Convert to integer
    ToFloat,       // Convert to float
    GetLength,     // Get length of an object or string
    GetAt,         // Get value at an index
    SetAt,         // Set value at an index
    UpdateSize,    // Update size of an object or array
    GetAsciiCode,  // Get ASCII code of a character
    ToUpper,       // Convert to uppercase
    ToLower,       // Convert to lowercase
    MakeUpper,     // Make string uppercase
    MakeLower,     // Make string lowercase
    FindSubString, // Find a substring within a string

    // OPCODE_ANGLE_3D (vector and matrix operations)
    Dot,             // Dot product of vectors
    Cross,           // Cross product of vectors
    ApplyQuaternion, // Apply quaternion transformation
    SetX,            // Set X component
    SetY,            // Set Y component
    SetZ,            // Set Z component
    SetXY,           // Set XY components
    SetXYZ,          // Set XYZ components

    // OPCODE_BOOL
    AssignOR,
    AssignXOR,
    AssignAND,
    NOT,
    OR,
    XOR,
    AND,

    // No idea what these do yet
    GetAlpha,
    GetBeta,
    GetGamma,
    SetAlpha,
    SetBeta,
    SetGamma,

    // Error Handling and Debug
    Fail,    // Fail operation
    GetName, // Get name of an object or function

    // Stack Operations
    Dup,         // Duplicate top of the stack
    AddSP,       // Add to stack pointer
    AddSP_8,     // Add 8 to stack pointer
    AddSP_20,    // Add 20 to stack pointer
    AddSP_M8,    // Subtract 8 from stack pointer
    AddSP_M20,   // Subtract 20 from stack pointer
    AddLongSP,   // Add long value to stack pointer
    AddOnSP,     // Add value on stack pointer
    LongAddOnSP, // Long add value on stack pointer
    Dereference, // Dereference pointer

    // Linking and Unlinking
    Link,  // Link objects or data
    Unlink // Unlink objects or data
};

int main()
{
}
