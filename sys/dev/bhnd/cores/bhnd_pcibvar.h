/*-
 * Copyright (c) 2015 Landon Fuller <landon@landonf.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * $FreeBSD$
 */

#ifndef _BHND_CORES_PCIBVAR_H_
#define _BHND_CORES_PCIBVAR_H_

#define	BHND_PCIB_MAX_RES	2
#define	BHND_PCIB_MAX_RSPEC	(BHND_PCIB_MAX_RES+1)

/* Device register definitions */
typedef enum {
	BHNDB_PCIB_RDEFS_PCI	= 0,	/* PCI register definitions */
	BHNDB_PCIB_RDEFS_PCIE	= 1,	/* PCIe-Gen1 register definitions */
} bhndb_pcib_rdefs_t;

/* Common BHND_PCI_*_REG_(GET|SET) implementation */
#define	_BHND_PCI_REG_GET(_regval, _mask, _shift)		\
	((_regval & _mask) >> _shift)
#define _BHND_PCI_REG_SET(_regval, _mask, _shift, _setval)	\
	(((_regval) & ~ _mask) | (((_setval) << _shift) & _mask))

/**
 * Extract a register value by applying _MASK and _SHIFT defines.
 * 
 * @param _regv The register value containing the desired attribute
 * @param _attr The register attribute name to which to append `_MASK`/`_SHIFT`
 * suffixes.
 */
#define	BHND_PCIB_REG_GET(_regv, _attr)	\
	_BHND_PCI_REG_GET(_regv, _attr ## _MASK, _attr ## _SHIFT)

/**
 * Set a register value by applying _MASK and _SHIFT defines.
 * 
 * @param _regv The register value containing the desired attribute
 * @param _attr The register attribute name to which to append `_MASK`/`_SHIFT`
 * suffixes.
 * @param _val The value to bet set in @p _regv.
 */
#define	BHND_PCIB_REG_SET(_regv, _attr, _val)		\
	_BHND_PCI_REG_SET(_regv, _attr ## _MASK, _attr ## _SHIFT, _val)

/**
 * Extract a register value by applying _MASK and _SHIFT defines to the common
 * PCI/PCIe register definition @p _regv
 * 
 * @param _sc The pcib device state.
 * @param _regv The register value containing the desired attribute
 * @param _attr The register attribute name to which to prepend the register
 * definition prefix and append `_MASK`/`_SHIFT` suffixes.
 */
#define BHND_PCIB_COMMON_REG_GET(_sc, _regv, _attr)	\
	_BHND_PCI_REG_GET(_regv,			\
	    BHND_PCIB_COMMON_REG(sc, _attr ## _MASK),	\
	    BHND_PCIB_COMMON_REG(sc, _attr ## _SHIFT))

/**
 * Set a register value by applying _MASK and _SHIFT defines to the common
 * PCI/PCIe register definition @p _regv
 * 
 * @param _sc The pcib device state.
 * @param _regv The register value containing the desired attribute
 * @param _attr The register attribute name to which to prepend the register
 * definition prefix and append `_MASK`/`_SHIFT` suffixes.
 * @param _val The value to bet set in @p _regv.
 */
#define BHND_PCIB_COMMON_REG_SET(_sc, _regv, _attr, _val)	\
	_BHND_PCI_REG_SET(_regv,				\
	    BHND_PCIB_COMMON_REG(sc, _attr ## _MASK),		\
	    BHND_PCIB_COMMON_REG(sc, _attr ## _SHIFT),		\
	    _val)


/**
 * Evaluates to the offset of a common PCI/PCIe register definition. 
 * 
 * This will trigger a compile-time error if the register is not defined
 * for all supported PCI/PCIe cores.
 * 
 * This should be optimized down to a constant value if the register constant
 * is the same across the register definitions.
 */
#define	BHND_PCIB_COMMON_REG(_sc, _name)	(			\
	(_sc)->rdefs == BHNDB_PCIB_RDEFS_PCI ? BHND_PCI_ ## _name :	\
	BHND_PCIE_ ## _name						\
)


struct bhnd_pcib_softc {
	device_t		 dev;	/**< pci device */
	struct bhnd_resource	*core;	/**< core registers. */
	bhndb_pcib_rdefs_t	 rdefs;	/**< device register definitions */

	struct resource_spec	 rspec[BHND_PCIB_MAX_RSPEC];
	struct bhnd_resource	*res[BHND_PCIB_MAX_RES];

};

#endif /* _BHND_CORES_PCIBVAR_H_ */