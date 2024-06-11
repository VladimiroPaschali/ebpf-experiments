use std::{error::Error, fmt};

#[derive(Debug)]
pub struct InxpectServerErr {
    code: i32,
    message: &'static str,
}

impl Error for InxpectServerErr {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for InxpectServerErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl InxpectServerErr {
    fn new(code: i32, message: &'static str) -> Self {
        Self { code, message }
    }
    pub fn get_err(code: i32) -> InxpectServerErr {
        match code {
            0 => InxpectServerErr::new(0, "None"),
            1 => InxpectServerErr::new(1, "Unknown Command"),
            2 => InxpectServerErr::new(2, "Invalid"),
            3 => InxpectServerErr::new(3, "Internal"),
            _ => InxpectServerErr::new(4, "Unknown"),
        }
    }
}

/* const UNKNOWN: InxpectServerErr = InxpectServerErr {
    code: -1,
    message: "Unknown error",
};

const NONE: InxpectServerErr = InxpectServerErr {
    code: 0,
    message: "Success!",
};

const UNKNOWN_CMD: InxpectServerErr = InxpectServerErr {
    code: 1,
    message: "Bad request",
};

const INVALID: InxpectServerErr = InxpectServerErr {
    code: 2,
    message: "Arguments not valid",
};

const INTERNAL: InxpectServerErr = InxpectServerErr {
    code: 3,
    message: "Internal Server Error",
};
 */