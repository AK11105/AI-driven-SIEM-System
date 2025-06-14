import React, { useState } from 'react';
import { FaShieldAlt, FaHome, FaClipboardList, FaExclamationTriangle, FaBars } from 'react-icons/fa';
import Link from 'next/link';

function Navbar() {
    const [isMenuOpen, setIsMenuOpen] = useState(false);

    return (
        <nav className="relative flex flex-wrap justify-between items-center px-4 sm:px-6 py-3 sm:py-4 bg-gradient-to-r from-[#1a1f2c] to-[#2c3e50] text-white shadow-lg border-b-2 border-[#00ff9d]">
            <div className="flex items-center gap-2 sm:gap-3">
                <FaShieldAlt className="text-xl sm:text-2xl text-[#00ff9d]" />
                <span className="text-lg sm:text-2xl font-bold tracking-wider bg-gradient-to-r from-[#3cdb9e] to-[#00ff9d] bg-clip-text text-transparent">
                    SIEM Dashboard
                </span>
            </div>

            {/* Mobile menu button */}
            <button 
                className="md:hidden p-2 rounded-lg hover:bg-[#00ff9d]/10"
                onClick={() => setIsMenuOpen(!isMenuOpen)}
            >
                <FaBars className="text-[#00ff9d] text-xl" />
            </button>

            {/* Navigation links */}
            <ul className={`
                ${isMenuOpen ? 'flex' : 'hidden'} 
                md:flex flex-col md:flex-row
                absolute md:relative
                top-full left-0
                w-full md:w-auto
                mt-2 md:mt-0
                bg-[#1a1f2c] md:bg-transparent
                border-b md:border-0 border-[#00ff9d]/20
                md:gap-4 lg:gap-6 
                list-none m-0 p-0
                md:items-center
            `}>
                <li className="w-full md:w-auto">
                    <Link href="/" 
                        className="flex items-center gap-2 text-white no-underline text-sm sm:text-base px-3 py-2 rounded transition-all duration-300 ease-in-out hover:bg-[#00ff9d]/10 hover:-translate-y-0.5"
                        onClick={() => setIsMenuOpen(false)}
                    >
                        <FaHome className="text-sm sm:text-base text-[#00ff9d]" />
                        <span className='font-semibold'>Home</span>
                    </Link>
                </li>
                <li className="w-full md:w-auto">
                    <Link href="/pages/logs" 
                        className="flex items-center gap-2 text-white no-underline text-sm sm:text-base px-3 py-2 rounded transition-all duration-300 ease-in-out hover:bg-[#00ff9d]/10 hover:-translate-y-0.5"
                        onClick={() => setIsMenuOpen(false)}
                    >
                        <FaClipboardList className="text-sm sm:text-base text-[#00ff9d]" />
                        <span className='font-semibold'>Logs</span>
                    </Link>
                </li>
                <li className="w-full md:w-auto">
                    <Link href="/pages/threats" 
                        className="flex items-center gap-2 text-white no-underline text-sm sm:text-base px-3 py-2 rounded transition-all duration-300 ease-in-out hover:bg-[#00ff9d]/10 hover:-translate-y-0.5"
                        onClick={() => setIsMenuOpen(false)}
                    >
                        <FaExclamationTriangle className="text-sm sm:text-base text-[#00ff9d]" />
                        <span className='font-semibold'>System Health</span>
                    </Link>
                </li>
            </ul>
        </nav>
    );
}

export default Navbar;
